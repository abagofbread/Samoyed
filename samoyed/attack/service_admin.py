"""SkyArk-style service admins — FullS3Admin, FullKMSAdmin, etc.

These principals hold ``service:*`` on ``Resource: *``. That is not account-root /
AdministratorAccess, but it is still a standing crown jewel (read/encrypt all
data, mint cloud credentials via STS, spawn compute as any role via CFN/Lambda).

SCPs that apply to the account are clamped in ``collect_principal_actions``
(identity ∩ permissions boundary ∩ SCP Allow − SCP Deny) when a ScopeBoundary
node carries ``scp_allow_sets`` / ``scp_deny_actions``. Management accounts are
marked ``scp_exempt``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from samoyed.attack.analyzer import collect_principal_actions
from samoyed.attack.high_value import _add_privesc_to_outcome, _infer_provider, ensure_attack_outcome_node
from samoyed.attack.outcomes import (
    SERVICE_ADMIN_OUTCOME_TYPES,
    outcome_metadata,
)
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import MARKING_HIGH_VALUE, apply_marking
from samoyed.graph.model import GraphSnapshot


@dataclass(frozen=True)
class ServiceAdminSpec:
    outcome_type: str
    skyark_name: str
    action: str  # e.g. s3:*
    kind: str  # high_value_kind
    pattern_id: str


# Matches CyberArk AWStealth privilege types (13)–(18).
SERVICE_ADMIN_SPECS: tuple[ServiceAdminSpec, ...] = (
    ServiceAdminSpec(
        outcome_type="full-s3-admin",
        skyark_name="FullS3admin",
        action="s3:*",
        kind="full-s3-admin",
        pattern_id="aws-full-s3-admin",
    ),
    ServiceAdminSpec(
        outcome_type="full-kms-admin",
        skyark_name="FullKMSadmin",
        action="kms:*",
        kind="full-kms-admin",
        pattern_id="aws-full-kms-admin",
    ),
    ServiceAdminSpec(
        outcome_type="full-ec2-admin",
        skyark_name="FullEC2admin",
        action="ec2:*",
        kind="full-ec2-admin",
        pattern_id="aws-full-ec2-admin",
    ),
    ServiceAdminSpec(
        outcome_type="full-sts-admin",
        skyark_name="FullSTSadmin",
        action="sts:*",
        kind="full-sts-admin",
        pattern_id="aws-full-sts-admin",
    ),
    ServiceAdminSpec(
        outcome_type="full-cloudformation-admin",
        skyark_name="FullCloudformationAdmin",
        action="cloudformation:*",
        kind="full-cloudformation-admin",
        pattern_id="aws-full-cloudformation-admin",
    ),
    ServiceAdminSpec(
        outcome_type="full-lambda-admin",
        skyark_name="FullLambdaAdmin",
        action="lambda:*",
        kind="full-lambda-admin",
        pattern_id="aws-full-lambda-admin",
    ),
)


def enrich_service_admins(
    builder: GraphBuilder,
    *,
    provider: CloudProvider | None = None,
) -> dict[str, int]:
    """Mark FullS3/KMS/EC2/… admins and wire CAN_PRIVESC_TO service AttackOutcomes."""
    graph = builder.snapshot
    provider = provider or _infer_provider(graph) or CloudProvider.AWS

    outcomes = {
        spec.outcome_type: ensure_attack_outcome_node(builder, provider, spec.outcome_type)
        for spec in SERVICE_ADMIN_SPECS
    }
    stats = {
        "service_outcome_nodes": len(outcomes),
        "service_admins_marked": 0,
        "service_privesc_edges": 0,
    }

    for node_id, node in list(graph.nodes.items()):
        if node.props.get("concept_type") != "Identity":
            continue
        hits = classify_service_admins(graph, node_id, node.props)
        if not hits:
            continue

        # Prefer richer reason if already marked for another HVT; still record service kinds.
        kinds = node.props.setdefault("service_admin_kinds", [])
        if not isinstance(kinds, list):
            kinds = list(kinds) if kinds else []
            node.props["service_admin_kinds"] = kinds

        newly_marked = False
        if not node.props.get(MARKING_HIGH_VALUE):
            apply_marking(node.props, high_value=True, source="service-admin-catalog")
            newly_marked = True
        if newly_marked or not node.props.get("high_value_kind"):
            # Don't overwrite account-root / AdministratorAccess kinds.
            standing = node.props.get("high_value_kind")
            if not standing or standing.startswith("full-"):
                primary = hits[0]
                node.props["high_value_kind"] = primary["kind"]
                node.props["high_value_reason"] = primary["reason"]
        if not node.props.get("high_value_reason") and hits:
            node.props["high_value_reason"] = hits[0]["reason"]

        for hit in hits:
            if hit["kind"] not in kinds:
                kinds.append(hit["kind"])
            if _add_privesc_to_outcome(
                builder,
                graph,
                src_id=node_id,
                outcome_id=outcomes[hit["outcome_type"]],
                outcome_type=hit["outcome_type"],
                provider=provider,
                reason=hit["reason"],
                pattern_id=hit["pattern_id"],
                pattern_name=hit["skyark_name"],
            ):
                stats["service_privesc_edges"] += 1
        if newly_marked:
            stats["service_admins_marked"] += 1

    return stats


def classify_service_admins(
    graph: GraphSnapshot,
    node_id: str,
    props: dict[str, Any],
) -> list[dict[str, str]]:
    """Return list of service-admin hits for this identity (SkyArk-style)."""
    actions = collect_principal_actions(graph, node_id)
    hits: list[dict[str, str]] = []
    for spec in SERVICE_ADMIN_SPECS:
        if not _grants_service_star(graph, node_id, props, actions, spec.action):
            continue
        meta = outcome_metadata(CloudProvider.AWS, spec.outcome_type)
        hits.append(
            {
                "kind": spec.kind,
                "outcome_type": spec.outcome_type,
                "pattern_id": spec.pattern_id,
                "skyark_name": spec.skyark_name,
                "reason": (
                    f"SkyArk {spec.skyark_name}: grants {spec.action} on Resource * "
                    f"— {meta['outcome_display']}"
                ),
            }
        )
    return hits


def _grants_service_star(
    graph: GraphSnapshot,
    node_id: str,
    props: dict[str, Any],
    actions: set[str],
    action: str,
) -> bool:
    """True when principal can perform ``service:*`` against ``*`` (SkyArk Resource check)."""
    from samoyed.attack.analyzer import action_matches, collect_principal_scp_denies

    service = action.split(":", 1)[0].lower()
    denies = collect_principal_scp_denies(graph, node_id)
    if any(action_matches(d, action) for d in denies):
        return False
    has_action = action in actions or any(
        a.lower() == action or a.lower() == f"{service}:*" for a in actions
    )
    # Action * already implies service:* — unless SCP denies that service.
    if "*" in actions or "*:*" in actions:
        if any(action_matches(d, action) for d in denies):
            return False
        return True
    if not has_action:
        return False

    # Prefer explicit Resource:* evidence on edges / entitlements (SkyArk requires *).
    arn = str(props.get("arn") or props.get("native_id") or "")
    for dst, rel, eprops in graph.adjacency.get(node_id, []):
        act = str(eprops.get("action") or "").lower()
        if act != action.lower() and act != f"{service}:*" and act not in {"*", "*:*"}:
            continue
        resource = str(eprops.get("resource") or "")
        if _resource_is_unrestricted(resource, service):
            return True

    for ent in graph.nodes.values():
        if ent.props.get("concept_type") != "Entitlement":
            continue
        principal = ent.props.get("principal_arn") or ""
        if principal and principal != arn and principal != props.get("native_id"):
            continue
        ent_actions = [str(a).lower() for a in (ent.props.get("actions") or [])]
        if action.lower() not in ent_actions and f"{service}:*" not in ent_actions and "*" not in ent_actions:
            continue
        for resource in ent.props.get("resources") or ["*"]:
            if _resource_is_unrestricted(str(resource), service):
                return True
        # Entitlement present with the action but no resources listed — treat as *
        if not ent.props.get("resources"):
            return True

    # Action present on edges without resource metadata — still Flag (enum often omits Resource:*)
    if has_action:
        return True
    return False


def _resource_is_unrestricted(resource: str, service: str) -> bool:
    if not resource or resource == "*":
        return True
    # arn:aws:s3:::* or arn:aws:kms:*:*:key/*
    if resource.startswith("arn:aws:") and ":*" in resource:
        return True
    if service == "s3" and resource in {"arn:aws:s3:::*", "arn:aws:s3:::*/*"}:
        return True
    return False
