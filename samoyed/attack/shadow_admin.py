"""Shadow admin detection — AWS principals that aren't named admins but can become them.

A *shadow admin* has no blatant AdministratorAccess / IAMFullAccess / root standing,
yet owns a privilege-escalation edge into:
  - a materialised admin AttackOutcome, or
  - a blatant high-value identity (PassRole / CreateAccessKey / trust-policy abuse), or
  - an admin_outcome-tagged CAN_PRIVESC_TO self hop

Illustration: mark ``is_shadow_admin`` and bridge CAN_PRIVESC_TO → administrator /
iam-administration outcomes with ``mechanism=shadow-admin`` so paths and the UI
surface them distinctly from crown-jewel admins.
"""

from __future__ import annotations

from typing import Any

from samoyed.attack.high_value import (
    ensure_attack_outcome_node,
    _infer_provider,
)
from samoyed.attack.outcomes import (
    ADMIN_OUTCOME_TYPE,
    IAM_ADMIN_OUTCOME_TYPE,
    outcome_metadata,
)
from samoyed.cloud.concepts import CloudProvider
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot

MARKING_SHADOW_ADMIN = "is_shadow_admin"

# Standing grants that mean "already an admin", not a shadow.
BLATANT_ADMIN_KINDS = frozenset(
    {
        "account-root",
        "administrator-policy",
        "administrator-wildcard",
        "iam-full-access",
        "high-value-name",  # named Admin / SSO AdministratorAccess
    }
)

# Patterns that by themselves imply admin-equivalent if the principal isn't already admin.
DIRECT_ADMIN_PATTERNS = frozenset(
    {
        "aws-iam-attach-user-policy",
        "aws-iam-put-user-policy",
        "aws-iam-create-policy-version",
        "aws-iam-set-default-policy-version",
        "aws-iam-add-user-to-group",
        "aws-iam-star",
        "aws-star-admin",
    }
)


def enrich_shadow_admins(
    builder: GraphBuilder,
    *,
    provider: CloudProvider | None = None,
) -> dict[str, int]:
    """Mark shadow admins and wire them to admin AttackOutcome nodes."""
    graph = builder.snapshot
    provider = provider or _infer_provider(graph) or CloudProvider.AWS

    admin_outcome = ensure_attack_outcome_node(builder, provider, ADMIN_OUTCOME_TYPE)
    iam_outcome = ensure_attack_outcome_node(builder, provider, IAM_ADMIN_OUTCOME_TYPE)

    blatant_ids = _blatant_admin_ids(graph)
    stats = {"shadow_admins": 0, "shadow_privesc_edges": 0}

    for node_id, node in list(graph.nodes.items()):
        if node.props.get("concept_type") != "Identity":
            continue
        if node_id in blatant_ids:
            continue
        if node.props.get(MARKING_SHADOW_ADMIN):
            continue

        finding = classify_shadow_admin(graph, node_id, blatant_ids)
        if not finding:
            continue

        node.props[MARKING_SHADOW_ADMIN] = True
        node.props["shadow_admin_reason"] = finding["reason"]
        node.props["shadow_admin_mechanism"] = finding["mechanism"]
        node.props["shadow_admin_via"] = finding.get("via")
        node.props["marking_source"] = node.props.get("marking_source") or "shadow-admin"
        stats["shadow_admins"] += 1

        outcome_id = iam_outcome if finding.get("iam_only") else admin_outcome
        outcome_type = IAM_ADMIN_OUTCOME_TYPE if finding.get("iam_only") else ADMIN_OUTCOME_TYPE
        if _add_shadow_privesc(
            builder,
            graph,
            src_id=node_id,
            outcome_id=outcome_id,
            outcome_type=outcome_type,
            provider=provider,
            finding=finding,
        ):
            stats["shadow_privesc_edges"] += 1

    return stats


def classify_shadow_admin(
    graph: GraphSnapshot,
    node_id: str,
    blatant_ids: set[str] | None = None,
) -> dict[str, Any] | None:
    """Return shadow-admin finding for a principal, or None."""
    blatant_ids = blatant_ids if blatant_ids is not None else _blatant_admin_ids(graph)
    if node_id in blatant_ids:
        return None
    node = graph.nodes.get(node_id)
    if not node or node.props.get("concept_type") != "Identity":
        return None
    kind = node.props.get("high_value_kind")
    if kind in BLATANT_ADMIN_KINDS:
        return None

    # 1) Direct admin_outcome-tagged privesc (AttachUserPolicy, CreatePolicyVersion, …)
    for dst, rel, props in graph.adjacency.get(node_id, []):
        if rel != "CAN_PRIVESC_TO":
            continue
        pattern_id = str(props.get("pattern_id") or "")
        if props.get("attack_outcome") or pattern_id in DIRECT_ADMIN_PATTERNS:
            # Skip edges we ourselves added as shadow bridges
            if props.get("mechanism") == "shadow-admin":
                continue
            if props.get("source") == "high-value-catalog" and pattern_id.startswith("aws-administrator"):
                # That's standing admin, not shadow
                continue
            return {
                "reason": props.get("pattern_name")
                or props.get("outcome_display")
                or "Privilege escalation to administrator-equivalent",
                "mechanism": pattern_id or "admin-outcome-privesc",
                "via": dst,
                "iam_only": props.get("attack_outcome") == IAM_ADMIN_OUTCOME_TYPE
                or pattern_id in {"aws-iam-star"},
                "pattern_id": pattern_id,
            }

    # 2) CAN_PRIVESC_TO a blatant admin identity (PassRole / CreateAccessKey / trust abuse)
    for dst, rel, props in graph.adjacency.get(node_id, []):
        if rel != "CAN_PRIVESC_TO":
            continue
        if props.get("mechanism") == "shadow-admin":
            continue
        if dst not in blatant_ids:
            continue
        dst_node = graph.nodes.get(dst)
        dst_label = (
            (dst_node.props.get("display_name") or dst_node.props.get("name") or dst_node.props.get("native_id"))
            if dst_node
            else dst
        )
        pattern_id = str(props.get("pattern_id") or "privilege-escalation")
        return {
            "reason": f"{props.get('pattern_name') or pattern_id} → privileged principal {dst_label}",
            "mechanism": pattern_id,
            "via": dst,
            "iam_only": False,
            "pattern_id": pattern_id,
        }

    # 3) CAN_PRIVESC_TO an AttackOutcome node (materialised)
    for dst, rel, props in graph.adjacency.get(node_id, []):
        if rel != "CAN_PRIVESC_TO":
            continue
        if props.get("mechanism") == "shadow-admin":
            continue
        dst_node = graph.nodes.get(dst)
        if not dst_node or dst_node.props.get("concept_type") != "AttackOutcome":
            continue
        outcome = dst_node.props.get("attack_outcome") or dst_node.props.get("resource_type")
        if outcome not in {ADMIN_OUTCOME_TYPE, IAM_ADMIN_OUTCOME_TYPE}:
            continue
        # Already linked to outcome — still a shadow admin if not blatant
        return {
            "reason": dst_node.props.get("outcome_display") or str(outcome),
            "mechanism": str(props.get("pattern_id") or "attack-outcome"),
            "via": dst,
            "iam_only": outcome == IAM_ADMIN_OUTCOME_TYPE,
            "pattern_id": props.get("pattern_id"),
        }

    return None


def _blatant_admin_ids(graph: GraphSnapshot) -> set[str]:
    out: set[str] = set()
    for node_id, node in graph.nodes.items():
        if node.props.get("concept_type") != "Identity":
            continue
        kind = node.props.get("high_value_kind")
        if kind in BLATANT_ADMIN_KINDS:
            out.add(node_id)
            continue
        native = str(node.props.get("native_kind") or "")
        arn = str(node.props.get("arn") or node.props.get("native_id") or "")
        if native == "Root" or arn.endswith(":root"):
            out.add(node_id)
    return out


def _add_shadow_privesc(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    src_id: str,
    outcome_id: str,
    outcome_type: str,
    provider: CloudProvider,
    finding: dict[str, Any],
) -> bool:
    for dst, rel, props in graph.adjacency.get(src_id, []):
        if (
            rel == "CAN_PRIVESC_TO"
            and dst == outcome_id
            and (
                props.get("mechanism") == "shadow-admin"
                or props.get("attack_outcome") == outcome_type
            )
        ):
            # Already reaches this outcome
            if props.get("mechanism") == "shadow-admin":
                return False
            # Ensure marking on existing edge
            props.setdefault("shadow_admin", True)
            return False

    meta = outcome_metadata(provider, outcome_type)
    builder.add_edge(
        src_id=src_id,
        rel_type="CAN_PRIVESC_TO",
        dst_id=outcome_id,
        props=enrichment_edge_props(
            source="shadow-admin",
            mechanism="shadow-admin",
            pattern_id=finding.get("pattern_id") or "shadow-admin",
            pattern_name=f"Shadow admin: {finding.get('reason')}",
            severity="critical",
            inferred=True,
            confidence="wildcard",
            shadow_admin=True,
            shadow_admin_via=finding.get("via"),
            **meta,
        ),
    )
    return True
