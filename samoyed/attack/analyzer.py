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
        "ECSService",
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


def find_identity_principals(graph: GraphSnapshot) -> list[str]:
    """All Identity nodes worth analyzing for privesc (not only is_caller)."""
    out: list[str] = []
    for node_id, node in graph.nodes.items():
        if node.label == "CollectionSession":
            continue
        if node.props.get("concept_type") == "Identity":
            out.append(node_id)
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

    # Prefer callers when provided; otherwise analyze every Identity with actions so
    # shadow-admin roles (instance/task/deployer) get CAN_PRIVESC_TO edges too.
    if start_node_ids is not None:
        principals = list(start_node_ids)
    else:
        principals = list(find_caller_nodes(graph))
        seen = set(principals)
        for nid in find_identity_principals(graph):
            if nid in seen:
                continue
            if collect_principal_actions(graph, nid):
                principals.append(nid)
                seen.add(nid)
        if not principals:
            principals = find_identity_principals(graph)

    results: list[AttackEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()

    for start_id in principals:
        actions = collect_principal_actions(graph, start_id)
        if not actions:
            continue
        for pattern in patterns:
            if not has_required_actions(actions, pattern.required_actions):
                continue
            for dst_id in _resolve_targets(graph, start_id, pattern, provider):
                key = (start_id, dst_id, pattern.id)
                if key in seen_edges:
                    continue
                seen_edges.add(key)
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
    from samoyed.attack.high_value import ensure_attack_outcome_node

    edges = analyze_attack_surface(
        builder.snapshot,
        provider=provider,
        start_node_ids=start_node_ids,
    )
    # One CAN_PRIVESC_TO per (src, dst) — keep the most specific pattern.
    best: dict[tuple[str, str], AttackEdge] = {}
    for edge in edges:
        dst_id = edge.dst_id
        if edge.pattern.target == "admin_outcome":
            outcome_type = str(
                edge.props.get("attack_outcome")
                or admin_outcome_metadata(provider).get("attack_outcome")
                or "administrator-access"
            )
            dst_id = ensure_attack_outcome_node(builder, provider, outcome_type)
        elif dst_id == edge.src_id and edge.props.get("attack_outcome"):
            dst_id = ensure_attack_outcome_node(
                builder,
                provider,
                str(edge.props["attack_outcome"]),
            )

        key = (edge.src_id, dst_id)
        resolved = AttackEdge(
            src_id=edge.src_id,
            dst_id=dst_id,
            pattern=edge.pattern,
            props=edge.props,
        )
        prev = best.get(key)
        if prev is None or _pattern_specificity(resolved.pattern) > _pattern_specificity(prev.pattern):
            best[key] = resolved

    applied: list[AttackEdge] = []
    for edge in best.values():
        builder.add_edge(
            src_id=edge.src_id,
            rel_type="CAN_PRIVESC_TO",
            dst_id=edge.dst_id,
            props=edge.props,
        )
        applied.append(edge)
    enrich_graph_edges(builder.snapshot)
    return applied


# PassRole launch patterns → IAM trust service principal that can assume the passed role.
_PASSROLE_TRUST_SERVICE: dict[str, str] = {
    "aws-ec2-run-instances": "ec2.amazonaws.com",
    "aws-ec2-passrole-ssm": "ec2.amazonaws.com",
    "aws-ec2-associate-instance-profile": "ec2.amazonaws.com",
    "aws-iam-passrole-instance-profile": "ec2.amazonaws.com",
    "aws-iam-create-instance-profile-passrole": "ec2.amazonaws.com",
    "aws-lambda-create-invoke": "lambda.amazonaws.com",
    "aws-lambda-create-invoke-url": "lambda.amazonaws.com",
    "aws-lambda-passrole-event-source": "lambda.amazonaws.com",
    "aws-lambda-passrole-add-permission": "lambda.amazonaws.com",
    "aws-ecs-run-task": "ecs-tasks.amazonaws.com",
    "aws-cloudformation-create-stack": "cloudformation.amazonaws.com",
    "aws-glue-passrole-dev-endpoint": "glue.amazonaws.com",
    "aws-sagemaker-passrole-notebook": "sagemaker.amazonaws.com",
    "aws-datapipeline-passrole": "datapipeline.amazonaws.com",
    "aws-states-test-state": "states.amazonaws.com",
}

_RUNTIME_CONTROL_RELS = frozenset({"CONTROLS", "WRITES", "EXECUTES", "DELETES"})


def _resolve_targets(
    graph: GraphSnapshot,
    start_id: str,
    pattern: AttackPattern,
    provider: CloudProvider,
) -> list[str]:
    if pattern.target == "admin_outcome":
        return [start_id]

    trust_service = _PASSROLE_TRUST_SERVICE.get(pattern.id)
    if trust_service and "iam:PassRole" in pattern.required_actions:
        trusted = _roles_assumable_by_service(graph, trust_service, exclude=start_id)
        preferred = _prefer_privileged_targets(graph, trusted, exclude=start_id)
        if preferred or trusted:
            return preferred or trusted[:25]
        # Explicit PassRole capability edges to concrete roles (tests / scoped policies).
        passed = _roles_targeted_by_passrole(graph, start_id, exclude=start_id)
        if passed:
            pref = _prefer_privileged_targets(graph, passed, exclude=start_id)
            return pref or passed
        # Last resort: standing high-value roles only — never every role in the account.
        roles = [
            rid
            for rid in _identity_nodes(graph, kind="Role", exclude=start_id)
            if not _is_service_linked_role_id(rid, graph)
        ]
        return _prefer_privileged_targets(graph, roles, exclude=start_id)

    if pattern.target == "execution_roles":
        # Only roles actually attached to inventored/controlled runtimes.
        # Never fall back to every IAM role (SecretsManagerReadWrite UFC FP).
        roles = execution_role_nodes(graph)
        via_control = _execution_roles_via_controlled_runtimes(graph, start_id, exclude=start_id)
        combined = _dedupe_keep_order([*via_control, *roles])
        preferred = _prefer_privileged_targets(graph, combined, exclude=start_id)
        return preferred or combined

    if pattern.target == "runtime_bindings":
        return _runtime_binding_nodes(graph)

    if pattern.target == "stored_identities":
        stored = stored_identity_nodes(graph, start_id)
        preferred = _prefer_privileged_targets(graph, stored, exclude=start_id)
        # No "every User in the account" fallback.
        return preferred or stored

    if pattern.target == "any_role":
        roles = [
            rid
            for rid in _identity_nodes(graph, kind="Role", exclude=start_id)
            if not _is_service_linked_role_id(rid, graph)
        ]
        preferred = _prefer_privileged_targets(graph, roles, exclude=start_id)
        # Prefer standing admins; otherwise a bounded slice of non-service-linked roles.
        return preferred or roles[:25]

    if pattern.target == "any_user":
        users = _identity_nodes(graph, kind="User", exclude=start_id)
        preferred = _prefer_privileged_targets(graph, users, exclude=start_id)
        return preferred or users[:25]

    if pattern.target == "assumable_roles":
        assumable: list[str] = []
        for dst, rel, _props in graph.adjacency.get(start_id, []):
            if rel == "CAN_ASSUME_ROLE" and dst in graph.nodes:
                assumable.append(dst)
        preferred = _prefer_privileged_targets(graph, assumable, exclude=start_id)
        # No all-roles fallback when the principal has no AssumeRole edges.
        return preferred or assumable

    return []


def _roles_targeted_by_passrole(
    graph: GraphSnapshot,
    start_id: str,
    *,
    exclude: str,
) -> list[str]:
    """Concrete Identity roles this principal CONTROLS via iam:PassRole."""
    out: list[str] = []
    seen: set[str] = set()
    for dst, rel, props in graph.adjacency.get(start_id, []):
        if rel not in {"CONTROLS", "WRITES", "EXECUTES"}:
            continue
        action = str(props.get("action") or "")
        if not action_matches(action, "iam:PassRole"):
            continue
        if dst == exclude or dst in seen:
            continue
        node = graph.nodes.get(dst)
        if not node or node.props.get("concept_type") != "Identity":
            continue
        if _is_service_linked_role_id(dst, graph):
            continue
        seen.add(dst)
        out.append(dst)
    return out


def _pattern_specificity(pattern: AttackPattern) -> int:
    """Higher wins when multiple patterns claim the same src→dst privesc edge."""
    score = len(pattern.required_actions) * 10
    if "PassRole" in pattern.name or "passrole" in pattern.id:
        score += 50
    if pattern.target == "admin_outcome":
        score += 40
    if pattern.severity == "critical":
        score += 5
    return score


def _dedupe_keep_order(ids: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for nid in ids:
        if nid in seen:
            continue
        seen.add(nid)
        out.append(nid)
    return out


def _is_service_linked_role_id(node_id: str, graph: GraphSnapshot) -> bool:
    node = graph.nodes.get(node_id)
    hay = node_id
    if node:
        hay = f"{node_id} {node.props.get('arn', '')} {node.props.get('native_id', '')}"
    return "/aws-service-role/" in hay or ":role/aws-service-role/" in hay


def _is_runtime_like_node(node_id: str, graph: GraphSnapshot) -> bool:
    node = graph.nodes.get(node_id)
    if not node:
        return False
    concept = node.props.get("concept_type")
    rtype = str(node.props.get("resource_type") or "")
    if concept == "RuntimeBinding" or rtype in RUNTIME_RESOURCE_TYPES:
        return True
    native = str(node.props.get("native_id") or node_id)
    return any(
        token in native or token in rtype
        for token in ("LambdaFunction", "Lambda:", "ECSTask", "EC2Instance", "CloudFunction")
    )


def _execution_roles_via_controlled_runtimes(
    graph: GraphSnapshot,
    start_id: str,
    *,
    exclude: str,
) -> list[str]:
    """Roles of runtimes this principal can mutate (CONTROLS/WRITES/… → EXECUTES_AS)."""
    out: list[str] = []
    seen: set[str] = set()
    for dst, rel, _props in graph.adjacency.get(start_id, []):
        if rel not in _RUNTIME_CONTROL_RELS:
            continue
        if not _is_runtime_like_node(dst, graph):
            continue
        for role_id, role_rel, _rp in graph.adjacency.get(dst, []):
            if role_rel != "EXECUTES_AS" or role_id == exclude or role_id in seen:
                continue
            if graph.nodes.get(role_id) and graph.nodes[role_id].props.get("concept_type") == "Identity":
                seen.add(role_id)
                out.append(role_id)
    return out


def _roles_assumable_by_service(
    graph: GraphSnapshot,
    service: str,
    *,
    exclude: str,
) -> list[str]:
    """Roles that trust a service principal (e.g. ec2.amazonaws.com → ec2Deployer)."""
    service_ids = {
        f"Principal:Service:{service}",
        f"Service:{service}",
        service,
    }
    out: list[str] = []
    seen: set[str] = set()
    for src_id, node in graph.nodes.items():
        if src_id not in service_ids and not str(node.props.get("native_id") or "").endswith(service):
            # Also match Trust:* nodes that encode the service.
            if not (
                src_id.startswith("Trust:")
                and service in src_id
                and "->" in src_id
            ):
                continue
            # Trust:Service:ec2.amazonaws.com->arn:...:role/ec2Deployer-role
            role_arn = src_id.split("->", 1)[-1]
            role_id = role_arn if role_arn.startswith("Principal:") else f"Principal:{role_arn}"
            if role_id in graph.nodes and role_id != exclude and role_id not in seen:
                if not _is_service_linked_role_id(role_id, graph):
                    seen.add(role_id)
                    out.append(role_id)
            continue
        for dst, rel, _props in graph.adjacency.get(src_id, []):
            if rel != "CAN_ASSUME_ROLE":
                continue
            if dst == exclude or dst in seen:
                continue
            if _is_service_linked_role_id(dst, graph):
                continue
            if graph.nodes.get(dst) and graph.nodes[dst].props.get("concept_type") == "Identity":
                seen.add(dst)
                out.append(dst)
    return out

def _prefer_privileged_targets(
    graph: GraphSnapshot,
    candidates: list[str],
    *,
    exclude: str,
) -> list[str]:
    """Prefer identities that look like standing admins — key for shadow-admin hops."""
    from samoyed.attack.high_value import classify_identity_high_value

    preferred: list[str] = []
    for node_id in candidates:
        if node_id == exclude:
            continue
        node = graph.nodes.get(node_id)
        if not node:
            continue
        if node.props.get("is_high_value") or node.props.get("high_value_kind"):
            preferred.append(node_id)
            continue
        if classify_identity_high_value(graph, node_id, node.props):
            preferred.append(node_id)
    return preferred


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
