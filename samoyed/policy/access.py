from __future__ import annotations

from typing import Any

from samoyed.attack.analyzer import action_matches, collect_principal_actions
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.refs import resolve_node_ref
from samoyed.path_engine.search import find_attack_paths

MINING_ACTIONS = frozenset(
    {
        "ec2:RunInstances",
        "ec2:RequestSpotInstances",
        "ec2:RunScheduledInstances",
    }
)

ISOLATION_RANK = {
    "public": 0,
    "internet": 0,
    "dmz": 1,
    "internal": 2,
    "pci": 3,
    "cardholder": 3,
    "restricted": 4,
}


def can_principal_access_node(
    graph: GraphSnapshot,
    principal_ref: str,
    target_ref: str,
    *,
    action: str | None = None,
) -> dict[str, Any]:
    """Answer whether a principal can reach a target node via graph edges."""
    principal_id = resolve_node_ref(graph, principal_ref)
    target_id = resolve_node_ref(graph, target_ref)
    if not principal_id or not target_id:
        return {
            "allowed": False,
            "reason": "unresolved_endpoint",
            "principal": principal_ref,
            "target": target_ref,
        }

    direct = _direct_access(graph, principal_id, target_id, action=action)
    if direct["allowed"]:
        return {
            "allowed": True,
            "via": "direct",
            "principal": principal_id,
            "target": target_id,
            "edges": direct["edges"],
        }

    if action:
        actions = collect_principal_actions(graph, principal_id)
        if any(action_matches(a, action) for a in actions):
            return {
                "allowed": True,
                "via": "iam_action",
                "principal": principal_id,
                "target": target_id,
                "matched_actions": sorted(actions & {action} or actions),
            }

    paths = find_attack_paths(
        graph,
        start_node_id=principal_id,
        end_node_id=target_id,
        max_depth=8,
        max_paths=3,
    )
    if paths:
        return {
            "allowed": True,
            "via": "attack_path",
            "principal": principal_id,
            "target": target_id,
            "path_count": len(paths),
            "shortest_hops": min(len(p.node_ids) - 1 for p in paths),
        }

    return {
        "allowed": False,
        "via": None,
        "principal": principal_id,
        "target": target_id,
    }


def principal_has_crypto_mining_risk(graph: GraphSnapshot, principal_ref: str) -> dict[str, Any]:
    """Check if a principal could launch unrestricted compute (crypto mining risk)."""
    principal_id = resolve_node_ref(graph, principal_ref)
    if not principal_id:
        return {"at_risk": False, "reason": "unresolved_principal"}

    actions = collect_principal_actions(graph, principal_id)
    can_launch = any(action_matches(a, req) for a in actions for req in MINING_ACTIONS)
    can_pass_role = any(action_matches(a, "iam:PassRole") for a in actions)
    unrestricted = "*" in actions or "*:*" in actions

    at_risk = can_launch and (can_pass_role or unrestricted)
    return {
        "at_risk": at_risk,
        "principal": principal_id,
        "can_launch_compute": can_launch,
        "can_pass_role": can_pass_role,
        "unrestricted": unrestricted,
        "actions_sample": sorted(a for a in actions if a.startswith(("ec2:", "iam:")))[:12],
    }


def find_internet_write_exposures(graph: GraphSnapshot) -> list[dict[str, Any]]:
    exposures: list[dict[str, Any]] = []
    for node_id, node in graph.nodes.items():
        props = node.props
        if not props.get("public_write") and not props.get("internet_write"):
            continue
        exposures.append(
            {
                "node_id": node_id,
                "display_name": props.get("display_name") or props.get("name") or node_id,
                "resource_type": props.get("resource_type"),
                "sensitivity": props.get("sensitivity"),
                "environment": props.get("environment"),
            }
        )
    return exposures


def find_isolation_breaches(graph: GraphSnapshot, *, max_depth: int = 8) -> list[dict[str, Any]]:
    """Find paths from internet-exposed compute to higher-sensitivity scopes."""
    breaches: list[dict[str, Any]] = []
    internet_nodes = [
        nid
        for nid, node in graph.nodes.items()
        if node.props.get("exposure_level") in {"internet", "public"}
        or node.props.get("has_public_url")
        or node.props.get("public_write")
    ]
    sensitive_targets = [
        (nid, node)
        for nid, node in graph.nodes.items()
        if _sensitivity_rank(node.props) >= ISOLATION_RANK["pci"]
    ]

    for start in internet_nodes:
        start_rank = _sensitivity_rank(graph.nodes[start].props)
        for target_id, target_node in sensitive_targets:
            target_rank = _sensitivity_rank(target_node.props)
            if target_rank <= start_rank:
                continue
            paths = find_attack_paths(
                graph,
                start_node_id=start,
                end_node_id=target_id,
                max_depth=max_depth,
                max_paths=1,
            )
            if paths:
                breaches.append(
                    {
                        "from": start,
                        "to": target_id,
                        "from_exposure": graph.nodes[start].props.get("display_name") or start,
                        "to_sensitivity": target_node.props.get("sensitivity")
                        or target_node.props.get("environment"),
                        "hops": len(paths[0].node_ids) - 1,
                    }
                )
    return breaches


def _direct_access(
    graph: GraphSnapshot,
    principal_id: str,
    target_id: str,
    *,
    action: str | None,
) -> dict[str, Any]:
    edges: list[dict[str, Any]] = []
    for dst, rel, props in graph.adjacency.get(principal_id, []):
        if dst != target_id:
            continue
        if action and props.get("action") and props.get("action") != action:
            continue
        if rel in {"READS", "WRITES", "DELETES", "CONTROLS", "EXECUTES", "CAN_ASSUME_ROLE", "CAN_ACCESS"}:
            edges.append({"rel": rel, **props})
    return {"allowed": bool(edges), "edges": edges}


def _sensitivity_rank(props: dict[str, Any]) -> int:
    for key in ("sensitivity", "environment", "scope_boundary"):
        value = str(props.get(key) or "").lower()
        if value in ISOLATION_RANK:
            return ISOLATION_RANK[value]
        if "pci" in value or "cardholder" in value:
            return ISOLATION_RANK["pci"]
        if "internal" in value:
            return ISOLATION_RANK["internal"]
    if props.get("public_write") or props.get("has_public_url"):
        return ISOLATION_RANK["internet"]
    return ISOLATION_RANK["internal"]
