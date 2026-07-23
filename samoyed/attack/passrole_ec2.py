"""Expand PassRole+RunInstances privesc onto inventored EC2 instances.

``CAN_PRIVESC_TO`` already targets roles that trust ``ec2.amazonaws.com``.
Blast still dead-ends on ``EC2Instance:*`` unless we also reach instances that
already ``EXECUTES_AS`` those passable roles.
"""

from __future__ import annotations

from typing import Any

from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot

# PassRole launch patterns that attach an instance profile / run EC2 as the role.
_EC2_PASSROLE_PATTERN_IDS = frozenset(
    {
        "aws-ec2-run-instances",
        "aws-ec2-passrole-ssm",
        "aws-ec2-associate-instance-profile",
        "aws-iam-passrole-instance-profile",
        "aws-iam-create-instance-profile-passrole",
    }
)


def enrich_passrole_ec2_bindings(builder: GraphBuilder) -> dict[str, int]:
    """Principal → inventored EC2 that EXECUTES_AS a PassRole target role."""
    graph = builder.snapshot
    role_to_ec2s = _ec2s_by_execution_role(graph)
    if not role_to_ec2s:
        return {"passrole_ec2_bindings": 0, "ec2_with_roles": 0}

    added = 0
    for edge in list(graph.edges):
        if edge.rel_type != "CAN_PRIVESC_TO":
            continue
        if not _is_ec2_passrole_edge(edge.props):
            continue
        role_id = edge.dst_id
        for ec2_id in role_to_ec2s.get(role_id, []):
            if _add_executes(builder, graph, edge.src_id, ec2_id, role_id, edge.props):
                added += 1

    return {
        "passrole_ec2_bindings": added,
        "ec2_with_roles": sum(len(v) for v in role_to_ec2s.values()),
    }


def _is_ec2_passrole_edge(props: dict[str, Any]) -> bool:
    pattern_id = str(props.get("pattern_id") or "")
    if pattern_id in _EC2_PASSROLE_PATTERN_IDS:
        return True
    actions = props.get("required_actions") or []
    action_text = " ".join(str(a) for a in actions).lower()
    name = str(props.get("pattern_name") or "").lower()
    if "passrole" not in action_text and "passrole" not in name and "passrole" not in pattern_id:
        return False
    return any(
        tok in action_text or tok in name or tok in pattern_id
        for tok in ("runinstances", "ec2", "instance-profile", "ssm")
    )


def _ec2s_by_execution_role(graph: GraphSnapshot) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for node_id, node in graph.nodes.items():
        if not _is_inventored_ec2(node):
            continue
        for dst, rel, _props in graph.adjacency.get(node_id, []):
            if rel != "EXECUTES_AS":
                continue
            out.setdefault(dst, []).append(node_id)
    return out


def _is_inventored_ec2(node: Any) -> bool:
    native = str(node.props.get("native_id") or "")
    if "*" in native or native.endswith(":*"):
        return False
    rtype = str(node.props.get("resource_type") or node.props.get("native_kind") or "")
    if rtype == "EC2Instance" or native.startswith("EC2Instance:"):
        return True
    concept = str(node.props.get("concept_type") or "")
    return concept == "RuntimeBinding" and "ec2" in rtype.lower()


def _add_executes(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    principal_id: str,
    ec2_id: str,
    role_id: str,
    privesc_props: dict[str, Any],
) -> bool:
    via_stub = _ec2_star_stub(graph, principal_id)
    for dst, rel, props in graph.adjacency.get(principal_id, []):
        if dst != ec2_id or rel not in {"EXECUTES", "CAN_PRIVESC_TO", "CONTROLS"}:
            continue
        # Refresh supersession markers on an existing inventored binding.
        if via_stub and not props.get("via_policy_resource"):
            props["via_policy_resource"] = via_stub
        if props.get("discovered_via") in {"passrole-ec2-inventory", "capability-glob"}:
            props.setdefault("via_role", role_id)
            return False
        if "*" not in str(props.get("resource") or ""):
            # Explicit inventored edge — stamp passrole provenance for blast stub omit.
            props["discovered_via"] = props.get("discovered_via") or "passrole-ec2-inventory"
            props["via_role"] = role_id
            if via_stub:
                props["via_policy_resource"] = via_stub
            return False
    builder.add_edge(
        src_id=principal_id,
        rel_type="EXECUTES",
        dst_id=ec2_id,
        props=enrichment_edge_props(
            source="passrole-ec2",
            discovered_via="passrole-ec2-inventory",
            mechanism="passrole-runinstances-inventory",
            via_role=role_id,
            via_policy_resource=via_stub,
            pattern_id=privesc_props.get("pattern_id"),
            pattern_name=privesc_props.get("pattern_name"),
            confidence="inferred",
            resource_type="EC2Instance",
        ),
    )
    return True


def _ec2_star_stub(graph: GraphSnapshot, principal_id: str) -> str | None:
    """Policy stub this principal EXECUTES (EC2Instance:*) for supersession."""
    for dst, rel, _props in graph.adjacency.get(principal_id, []):
        if rel not in {"EXECUTES", "CONTROLS"}:
            continue
        node = graph.nodes.get(dst)
        native = str((node.props.get("native_id") if node else None) or dst)
        if native == "EC2Instance:*" or native.endswith("EC2Instance:*"):
            return dst
    return None
