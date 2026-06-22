from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from samoyed.attack.mitre import enrich_graph_edges, mitre_props_for_edge
from samoyed.attack.outcomes import admin_outcome_metadata
from samoyed.attack.patterns import AttackPattern, patterns_for_provider
from samoyed.cloud.capabilities import azure_role_to_actions, gcp_role_to_actions
from samoyed.cloud.concepts import CloudProvider
from samoyed.enumerators.k8s.helpers import DANGEROUS_CLUSTER_ROLES
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot

RUNTIME_RESOURCE_TYPES = frozenset(
    {
        "LambdaFunction",
        "EC2Instance",
        "ECSTask",
        "CloudFunction",
    }
)


@dataclass
class AttackEdge:
    src_id: str
    dst_id: str
    pattern: AttackPattern
    props: dict[str, Any]


def action_matches(granted: str, required: str) -> bool:
    if granted == required:
        return True
    if granted in ("*", "*:*"):
        return True
    if granted.endswith(":*"):
        prefix = granted[:-2]
        return required == prefix or required.startswith(f"{prefix}:")
    return False


def has_required_actions(available: set[str], required: frozenset[str]) -> bool:
    return all(any(action_matches(a, req) for a in available) for req in required)


def collect_principal_actions(graph: GraphSnapshot, node_id: str) -> set[str]:
    actions: set[str] = set()
    node = graph.nodes.get(node_id)
    if not node:
        return actions

    for _dst, _rel, props in graph.adjacency.get(node_id, []):
        if props.get("action"):
            actions.add(str(props["action"]))
        if props.get("operation"):
            actions.add(str(props["operation"]))
        if props.get("role"):
            actions.update(gcp_role_to_actions(str(props["role"])))
            actions.update(azure_role_to_actions(str(props["role"])))

    native_id = node.props.get("native_id") or node.props.get("arn") or ""
    for ent in graph.nodes.values():
        if ent.props.get("concept_type") != "Entitlement":
            continue
        principal = ent.props.get("principal_arn") or ""
        members = ent.props.get("members") or []
        if principal != native_id and native_id not in members:
            continue
        for action in ent.props.get("actions") or []:
            actions.add(str(action))
        role = ent.props.get("role") or ent.props.get("role_name")
        if role:
            actions.update(gcp_role_to_actions(str(role)))
            actions.update(azure_role_to_actions(str(role)))

    for dst, rel, props in graph.adjacency.get(node_id, []):
        if props.get("rbac_rule"):
            actions.update(_k8s_actions_from_edge(rel, props))
        if rel == "CAN_ACCESS":
            dst_node = graph.nodes.get(dst)
            if dst_node and dst_node.props.get("concept_type") == "ManagementEndpoint":
                actions.add("rbac:cluster-admin")
        if props.get("role") in DANGEROUS_CLUSTER_ROLES:
            actions.add("rbac:cluster-admin")

    return actions


def _k8s_actions_from_edge(rel: str, props: dict[str, Any]) -> set[str]:
    rule = props.get("rbac_rule") or {}
    verbs = set(rule.get("verbs") or [])
    resources = set(rule.get("resources") or [])
    out: set[str] = set()
    if verbs & {"*"} and resources & {"*"}:
        out.add("rbac:cluster-admin")
    if verbs & {"*", "create", "update", "patch", "delete"} and (
        "secrets" in resources or "*" in resources
    ):
        out.add("rbac:secrets:write")
    if verbs & {"*", "create"} and ("pods" in resources or "*" in resources):
        out.add("rbac:pods:create")
    if verbs & {"*", "create"} and ("pods/exec" in resources or "*" in resources):
        out.add("rbac:pods:exec")
    return out


def find_caller_nodes(graph: GraphSnapshot) -> list[str]:
    callers: list[str] = []
    for node_id, node in graph.nodes.items():
        if node.label == "CollectionSession":
            continue
        if node.props.get("is_caller") or node.props.get("is_scenario_start"):
            callers.append(node_id)
        elif node.props.get("native_kind") == "CompromisedHost":
            callers.append(node_id)
    return callers


def execution_role_nodes(graph: GraphSnapshot) -> list[str]:
    roles: list[str] = []
    seen: set[str] = set()
    for src_id, node in graph.nodes.items():
        rtype = node.props.get("resource_type")
        concept = node.props.get("concept_type")
        if concept != "RuntimeBinding" and rtype not in RUNTIME_RESOURCE_TYPES:
            continue
        for dst_id, rel, _props in graph.adjacency.get(src_id, []):
            if rel != "EXECUTES_AS" or dst_id in seen:
                continue
            seen.add(dst_id)
            roles.append(dst_id)
    return roles


def stored_identity_nodes(graph: GraphSnapshot, start_id: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for dst_id, rel, _props in graph.adjacency.get(start_id, []):
        if rel not in {"LOGGED_IN_AS", "STORES_CREDS_FOR", "CAN_STEAL_CREDS_FROM"}:
            continue
        if dst_id not in seen:
            seen.add(dst_id)
            out.append(dst_id)
    return out


def analyze_attack_surface(
    graph: GraphSnapshot,
    *,
    provider: CloudProvider,
    start_node_ids: list[str] | None = None,
) -> list[AttackEdge]:
    patterns = patterns_for_provider(provider)
    if not patterns:
        return []

    principals = start_node_ids or find_caller_nodes(graph)
    if not principals:
        principals = [
            nid
            for nid, node in graph.nodes.items()
            if node.props.get("concept_type") == "Identity" and node.props.get("is_caller")
        ]

    results: list[AttackEdge] = []
    seen: set[tuple[str, str, str]] = set()

    for start_id in principals:
        actions = collect_principal_actions(graph, start_id)
        if not actions:
            continue
        for pattern in patterns:
            if not has_required_actions(actions, pattern.required_actions):
                continue
            for dst_id in _resolve_targets(graph, start_id, pattern, provider):
                key = (start_id, dst_id, pattern.id)
                if key in seen:
                    continue
                seen.add(key)
                edge_props = {
                    "pattern_id": pattern.id,
                    "pattern_name": pattern.name,
                    "pattern_description": pattern.description,
                    "severity": pattern.severity,
                    "source": pattern.source,
                    "required_actions": sorted(pattern.required_actions),
                    "inferred": True,
                    "confidence": "explicit",
                    **mitre_props_for_edge(
                        "CAN_PRIVESC_TO",
                        {"pattern_id": pattern.id, "action": next(iter(pattern.required_actions), "")},
                    ),
                }
                if pattern.target == "admin_outcome":
                    edge_props.update(admin_outcome_metadata(provider))
                results.append(
                    AttackEdge(
                        src_id=start_id,
                        dst_id=dst_id,
                        pattern=pattern,
                        props=edge_props,
                    )
                )
    return results


def apply_attack_analysis(
    builder: GraphBuilder,
    *,
    provider: CloudProvider,
    start_node_ids: list[str] | None = None,
) -> list[AttackEdge]:
    edges = analyze_attack_surface(
        builder.snapshot,
        provider=provider,
        start_node_ids=start_node_ids,
    )
    added: set[tuple[str, str, str]] = set()
    applied: list[AttackEdge] = []
    for edge in edges:
        key = (edge.src_id, "CAN_PRIVESC_TO", edge.dst_id)
        if key in added:
            continue
        added.add(key)
        builder.add_edge(
            src_id=edge.src_id,
            rel_type="CAN_PRIVESC_TO",
            dst_id=edge.dst_id,
            props=edge.props,
        )
        applied.append(edge)
    enrich_graph_edges(builder.snapshot)
    return applied


def _resolve_targets(
    graph: GraphSnapshot,
    start_id: str,
    pattern: AttackPattern,
    provider: CloudProvider,
) -> list[str]:
    if pattern.target == "admin_outcome":
        return [start_id]

    if pattern.target == "execution_roles":
        roles = execution_role_nodes(graph)
        return roles or _identity_nodes(graph, kind="Role", exclude=start_id)

    if pattern.target == "runtime_bindings":
        return _runtime_binding_nodes(graph)

    if pattern.target == "stored_identities":
        stored = stored_identity_nodes(graph, start_id)
        return stored or _identity_nodes(graph, kind="User", exclude=start_id)

    if pattern.target == "any_role":
        return _identity_nodes(graph, kind="Role", exclude=start_id)

    if pattern.target == "any_user":
        return _identity_nodes(graph, kind="User", exclude=start_id)

    if pattern.target == "assumable_roles":
        assumable: list[str] = []
        for dst, rel, _props in graph.adjacency.get(start_id, []):
            if rel == "CAN_ASSUME_ROLE" and dst in graph.nodes:
                assumable.append(dst)
        return assumable or _identity_nodes(graph, kind="Role", exclude=start_id)

    return []


def _runtime_binding_nodes(graph: GraphSnapshot) -> list[str]:
    out: list[str] = []
    for node_id, node in graph.nodes.items():
        concept = node.props.get("concept_type")
        rtype = node.props.get("resource_type")
        if concept == "RuntimeBinding" or rtype in RUNTIME_RESOURCE_TYPES:
            out.append(node_id)
    return out


def _identity_nodes(graph: GraphSnapshot, *, kind: str, exclude: str) -> list[str]:
    out: list[str] = []
    for node_id, node in graph.nodes.items():
        if node_id == exclude:
            continue
        if node.props.get("concept_type") != "Identity":
            continue
        native_kind = node.props.get("native_kind") or ""
        if kind == "Role" and (
            native_kind == "Role"
            or ":role/" in str(node.props.get("arn", ""))
            or native_kind == "ServiceAccount"
        ):
            out.append(node_id)
        elif kind == "User" and (
            native_kind == "User"
            or ":user/" in str(node.props.get("arn", ""))
            or str(node.props.get("native_id", "")).startswith(("gcp:user:", "azure:user:"))
        ):
            out.append(node_id)
        elif kind == "ServiceAccount" and native_kind == "ServiceAccount":
            out.append(node_id)
    return out
