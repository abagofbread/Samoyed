from __future__ import annotations

from typing import Any

from samoyed.change_impact.models import ProposedChange
from samoyed.graph.model import GraphEdge, GraphSnapshot
from samoyed.graph.refs import resolve_node_ref

ACTION_TO_REL = {
    "s3:GetObject": "READS",
    "s3:ListBucket": "READS",
    "s3:PutObject": "WRITES",
    "s3:DeleteObject": "DELETES",
    "secretsmanager:GetSecretValue": "READS",
    "secretsmanager:PutSecretValue": "WRITES",
    "sts:AssumeRole": "CAN_ASSUME_ROLE",
    "lambda:InvokeFunction": "EXECUTES",
    "lambda:UpdateFunctionCode": "CONTROLS",
    "ec2:RunInstances": "CONTROLS",
    "iam:PassRole": "CONTROLS",
}


def apply_changes(graph: GraphSnapshot, changes: list[ProposedChange]) -> list[dict[str, Any]]:
    applied: list[dict[str, Any]] = []
    for change in changes:
        entry = _apply_one(graph, change)
        if entry:
            applied.append(entry)
    return applied


def _apply_one(graph: GraphSnapshot, change: ProposedChange) -> dict[str, Any] | None:
    ctype = change.type.strip().lower().replace("-", "_")
    if ctype == "grant_action":
        return _grant_action(graph, change)
    if ctype == "revoke_action":
        return _revoke_action(graph, change)
    if ctype == "expose_resource":
        return _expose_resource(graph, change)
    if ctype == "restrict_resource":
        return _restrict_resource(graph, change)
    if ctype == "add_trust":
        return _add_trust(graph, change)
    if ctype == "set_property":
        return _set_property(graph, change)
    if ctype == "add_edge":
        return _add_edge(graph, change)
    raise ValueError(f"Unsupported change type: {change.type}")


def _resolve_node(graph: GraphSnapshot, ref: str | None) -> str | None:
    if not ref:
        return None
    return resolve_node_ref(graph, ref)


def _grant_action(graph: GraphSnapshot, change: ProposedChange) -> dict[str, Any]:
    src = _resolve_node(graph, change.principal)
    dst = _resolve_node(graph, change.target)
    if not src or not dst:
        raise ValueError("grant_action requires resolvable principal and target")
    action = change.action or ""
    rel = change.rel or ACTION_TO_REL.get(action) or _infer_rel(action)
    props = {"action": action, "source": "proposed-change", "confidence": "explicit", **change.properties}
    graph.add_edge(GraphEdge(src_id=src, rel_type=rel, dst_id=dst, props=props))
    return {"type": "grant_action", "from": src, "to": dst, "rel": rel, "action": action}


def _revoke_action(graph: GraphSnapshot, change: ProposedChange) -> dict[str, Any]:
    src = _resolve_node(graph, change.principal)
    dst = _resolve_node(graph, change.target)
    if not src or not dst:
        raise ValueError("revoke_action requires resolvable principal and target")
    action = change.action
    rel = change.rel
    removed = 0
    kept: list[GraphEdge] = []
    for edge in graph.edges:
        if edge.src_id != src or edge.dst_id != dst:
            kept.append(edge)
            continue
        if rel and edge.rel_type != rel:
            kept.append(edge)
            continue
        if action and edge.props.get("action") != action:
            kept.append(edge)
            continue
        removed += 1
    graph.edges = kept
    graph.adjacency = {}
    for edge in graph.edges:
        graph.adjacency.setdefault(edge.src_id, []).append(
            (edge.dst_id, edge.rel_type, edge.props)
        )
    return {"type": "revoke_action", "from": src, "to": dst, "removed": removed}


def _expose_resource(graph: GraphSnapshot, change: ProposedChange) -> dict[str, Any]:
    node_id = _resolve_node(graph, change.target)
    if not node_id:
        raise ValueError("expose_resource requires a resolvable target")
    node = graph.nodes[node_id]
    level = change.properties.get("exposure_level", "internet")
    node.props["exposure_level"] = level
    if change.properties.get("public_write") or change.properties.get("write"):
        node.props["public_write"] = True
    if change.properties.get("public_read") or change.properties.get("read"):
        node.props["public_read"] = True
    if level == "internet":
        node.props["publicly_accessible"] = True
    return {"type": "expose_resource", "target": node_id, "exposure_level": level}


def _restrict_resource(graph: GraphSnapshot, change: ProposedChange) -> dict[str, Any]:
    node_id = _resolve_node(graph, change.target)
    if not node_id:
        raise ValueError("restrict_resource requires a resolvable target")
    node = graph.nodes[node_id]
    node.props["exposure_level"] = "internal"
    node.props["internal_only"] = True
    node.props.pop("public_write", None)
    node.props.pop("public_read", None)
    node.props.pop("publicly_accessible", None)
    return {"type": "restrict_resource", "target": node_id}


def _add_trust(graph: GraphSnapshot, change: ProposedChange) -> dict[str, Any]:
    principal = _resolve_node(graph, change.principal)
    role = _resolve_node(graph, change.target)
    if not principal or not role:
        raise ValueError("add_trust requires principal and role target")
    graph.add_edge(
        GraphEdge(
            src_id=principal,
            rel_type="CAN_ASSUME_ROLE",
            dst_id=role,
            props={"source": "proposed-change", "confidence": "explicit", **change.properties},
        )
    )
    return {"type": "add_trust", "from": principal, "to": role}


def _set_property(graph: GraphSnapshot, change: ProposedChange) -> dict[str, Any]:
    node_id = _resolve_node(graph, change.target or change.principal)
    if not node_id:
        raise ValueError("set_property requires a resolvable target")
    node = graph.nodes[node_id]
    for key, value in change.properties.items():
        node.props[key] = value
    return {"type": "set_property", "target": node_id, "properties": change.properties}


def _add_edge(graph: GraphSnapshot, change: ProposedChange) -> dict[str, Any]:
    src = _resolve_node(graph, change.principal)
    dst = _resolve_node(graph, change.target)
    if not src or not dst or not change.rel:
        raise ValueError("add_edge requires principal, target, and rel")
    graph.add_edge(
        GraphEdge(
            src_id=src,
            rel_type=change.rel,
            dst_id=dst,
            props={"source": "proposed-change", "confidence": "explicit", **change.properties},
        )
    )
    return {"type": "add_edge", "from": src, "to": dst, "rel": change.rel}


def _infer_rel(action: str) -> str:
    if not action:
        return "CONTROLS"
    if action.startswith("s3:"):
        if "Put" in action or "Delete" in action:
            return "WRITES"
        return "READS"
    if action.startswith("secretsmanager:"):
        if "Put" in action:
            return "WRITES"
        return "READS"
    if action == "sts:AssumeRole":
        return "CAN_ASSUME_ROLE"
    return "CONTROLS"
