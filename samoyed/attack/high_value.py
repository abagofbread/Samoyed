"""Blatant high-value targets: account root, IAM admin, full administrator.

Auto-marks matching Identity nodes and materialises AttackOutcome crown jewels
so analyst / path queries (`high_value`, `AttackOutcome`) find them without
manual marking.
"""

from __future__ import annotations

from typing import Any

from samoyed.attack.analyzer import collect_principal_actions
from samoyed.attack.outcomes import (
    ACCOUNT_ROOT_OUTCOME_TYPE,
    ADMIN_OUTCOME_TYPE,
    IAM_ADMIN_OUTCOME_TYPE,
    outcome_metadata,
)
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.markings import MARKING_HIGH_VALUE, apply_marking
from samoyed.graph.model import GraphSnapshot

# Managed policies / role names that are blatant crown jewels.
HIGH_VALUE_POLICY_FRAGMENTS = (
    "AdministratorAccess",
    "IAMFullAccess",
    "OrganizationAccountAccessRole",
)

HIGH_VALUE_IDENTITY_NAME_FRAGMENTS = (
    "administrator",
    "admin",
    "OrganizationAccountAccessRole",
    "AWSReservedSSO_AdministratorAccess",
)

# Any of these on a principal ⇒ IAM administration outcome.
IAM_ADMIN_ACTIONS = frozenset(
    {
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:CreateGroup",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutGroupPolicy",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AddUserToGroup",
        "iam:UpdateAssumeRolePolicy",
        "iam:PassRole",
        "iam:*",
    }
)

# Full-account admin (broader than IAM-only).
FULL_ADMIN_ACTIONS = frozenset({"*", "*:*"})


def enrich_high_value_targets(
    builder: GraphBuilder,
    *,
    provider: CloudProvider | None = None,
) -> dict[str, int]:
    """Mark blatant HVT identities and wire CAN_PRIVESC_TO → AttackOutcome nodes."""
    graph = builder.snapshot
    provider = provider or _infer_provider(graph) or CloudProvider.AWS

    stats = {
        "outcome_nodes": 0,
        "identities_marked": 0,
        "privesc_to_outcome": 0,
    }

    outcomes = {
        ADMIN_OUTCOME_TYPE: ensure_attack_outcome_node(builder, provider, ADMIN_OUTCOME_TYPE),
        IAM_ADMIN_OUTCOME_TYPE: ensure_attack_outcome_node(
            builder, provider, IAM_ADMIN_OUTCOME_TYPE
        ),
        ACCOUNT_ROOT_OUTCOME_TYPE: ensure_attack_outcome_node(
            builder, provider, ACCOUNT_ROOT_OUTCOME_TYPE
        ),
    }
    stats["outcome_nodes"] = len(outcomes)

    for node_id, node in list(graph.nodes.items()):
        if node.props.get("concept_type") != "Identity":
            continue
        reason = classify_identity_high_value(graph, node_id, node.props)
        if not reason:
            continue
        if not node.props.get(MARKING_HIGH_VALUE):
            apply_marking(
                node.props,
                high_value=True,
                source="high-value-catalog",
            )
            node.props["high_value_reason"] = reason["reason"]
            node.props["high_value_kind"] = reason["kind"]
            stats["identities_marked"] += 1
        elif not node.props.get("high_value_reason"):
            node.props["high_value_reason"] = reason["reason"]
            node.props["high_value_kind"] = reason["kind"]

        # Root identity is itself the account-root outcome endpoint.
        if reason["kind"] == "account-root":
            if _add_privesc_to_outcome(
                builder,
                graph,
                src_id=node_id,
                outcome_id=outcomes[ACCOUNT_ROOT_OUTCOME_TYPE],
                outcome_type=ACCOUNT_ROOT_OUTCOME_TYPE,
                provider=provider,
                reason=reason["reason"],
                pattern_id="aws-account-root",
                pattern_name="Account root principal",
            ):
                stats["privesc_to_outcome"] += 1
            continue

        if reason["kind"] in {"administrator-policy", "administrator-wildcard"}:
            if _add_privesc_to_outcome(
                builder,
                graph,
                src_id=node_id,
                outcome_id=outcomes[ADMIN_OUTCOME_TYPE],
                outcome_type=ADMIN_OUTCOME_TYPE,
                provider=provider,
                reason=reason["reason"],
                pattern_id="aws-administrator-access",
                pattern_name="Administrator / full account control",
            ):
                stats["privesc_to_outcome"] += 1

        if reason["kind"] in {
            "iam-full-access",
            "iam-admin-actions",
            "administrator-policy",
            "administrator-wildcard",
            "high-value-name",
        }:
            if _add_privesc_to_outcome(
                builder,
                graph,
                src_id=node_id,
                outcome_id=outcomes[IAM_ADMIN_OUTCOME_TYPE],
                outcome_type=IAM_ADMIN_OUTCOME_TYPE,
                provider=provider,
                reason=reason["reason"],
                pattern_id="aws-iam-administration",
                pattern_name="IAM administration",
            ):
                stats["privesc_to_outcome"] += 1

    # Also link callers that match admin_outcome patterns (actions) even if not marked.
    for node_id, node in list(graph.nodes.items()):
        if node.props.get("concept_type") != "Identity":
            continue
        actions = collect_principal_actions(graph, node_id)
        if not actions:
            continue
        if actions & FULL_ADMIN_ACTIONS or any(
            a == "*" or a.endswith(":*") and a.split(":")[0] == "*" for a in actions
        ):
            if _add_privesc_to_outcome(
                builder,
                graph,
                src_id=node_id,
                outcome_id=outcomes[ADMIN_OUTCOME_TYPE],
                outcome_type=ADMIN_OUTCOME_TYPE,
                provider=provider,
                reason="principal grants Action *",
                pattern_id="aws-star-admin",
                pattern_name="Wildcard administrator",
            ):
                stats["privesc_to_outcome"] += 1
                if not node.props.get(MARKING_HIGH_VALUE):
                    apply_marking(node.props, high_value=True, source="high-value-catalog")
                    node.props["high_value_reason"] = "Action *"
                    node.props["high_value_kind"] = "administrator-wildcard"
                    stats["identities_marked"] += 1
        elif actions & IAM_ADMIN_ACTIONS or any(
            a == "iam:*" or (a.endswith(":*") and a.startswith("iam:")) for a in actions
        ):
            if _add_privesc_to_outcome(
                builder,
                graph,
                src_id=node_id,
                outcome_id=outcomes[IAM_ADMIN_OUTCOME_TYPE],
                outcome_type=IAM_ADMIN_OUTCOME_TYPE,
                provider=provider,
                reason="principal can modify IAM",
                pattern_id="aws-iam-modify",
                pattern_name="IAM modification capability",
            ):
                stats["privesc_to_outcome"] += 1

    return stats


def ensure_attack_outcome_node(
    builder: GraphBuilder,
    provider: CloudProvider,
    outcome_type: str,
) -> str:
    """Create (or reuse) a materialised AttackOutcome crown-jewel node."""
    meta = outcome_metadata(provider, outcome_type)
    native_id = f"AttackOutcome:{provider.value}:{outcome_type}"
    node_id = builder.add_concept_node(
        concept_type=ConceptType.ESCAPE_SURFACE,  # placeholder label; props override concept
        native_id=native_id,
        props={
            "concept_type": "AttackOutcome",
            "resource_type": outcome_type,
            "attack_outcome": outcome_type,
            "outcome_display": meta["outcome_display"],
            "display_name": meta["outcome_display"],
            "provider": provider.value,
            "blatant_high_value": True,
            MARKING_HIGH_VALUE: True,
            "marking_source": "high-value-catalog",
            "outcome_concept": "AttackOutcome",
        },
    )
    # add_concept_node may overwrite concept_type from enum — force AttackOutcome.
    node = builder.snapshot.nodes[node_id]
    node.label = "AttackOutcome"
    node.props["concept_type"] = "AttackOutcome"
    node.props[MARKING_HIGH_VALUE] = True
    node.props["marking_source"] = "high-value-catalog"
    return node_id


def classify_identity_high_value(
    graph: GraphSnapshot,
    node_id: str,
    props: dict[str, Any],
) -> dict[str, str] | None:
    """Return {kind, reason} if this identity is a blatant high-value target."""
    arn = str(props.get("arn") or props.get("native_id") or "")
    name = str(props.get("name") or props.get("display_name") or "").lower()
    native_kind = str(props.get("native_kind") or "")

    if native_kind == "Root" or arn.endswith(":root") or ":root" == arn[-5:]:
        return {"kind": "account-root", "reason": "AWS account root principal"}

    if ":root" in arn and "/root" not in arn and arn.rstrip("/").endswith("root"):
        return {"kind": "account-root", "reason": "AWS account root principal"}

    for frag in HIGH_VALUE_IDENTITY_NAME_FRAGMENTS:
        if frag.lower() in name or frag.lower() in arn.lower():
            # Avoid marking every "admin-readonly"-ish? Keep admin substring for blatant.
            if frag == "admin" and "admin" in name:
                # Skip mild false positives like "readonly-admin-audit" — still OK for lab.
                pass
            return {
                "kind": "high-value-name",
                "reason": f"Identity name/arn matches high-value fragment '{frag}'",
            }

    for ent in graph.nodes.values():
        if ent.props.get("concept_type") != "Entitlement":
            continue
        principal = ent.props.get("principal_arn") or ""
        if principal and principal != arn and principal != props.get("native_id"):
            continue
        if not principal:
            # Match via CONTROLS/READS edge from this identity? handled via actions below.
            pass
        policy_arn = str(ent.props.get("policy_arn") or ent.props.get("policy_name") or "")
        for frag in HIGH_VALUE_POLICY_FRAGMENTS:
            if frag in policy_arn:
                kind = (
                    "iam-full-access"
                    if frag == "IAMFullAccess"
                    else "administrator-policy"
                )
                return {
                    "kind": kind,
                    "reason": f"Attached/managed policy matches '{frag}'",
                }

    # Entitlements are linked by principal_arn — also walk edges for policy action *
    actions = collect_principal_actions(graph, node_id)
    if actions & FULL_ADMIN_ACTIONS:
        return {"kind": "administrator-wildcard", "reason": "Principal grants Action *"}
    if "iam:*" in actions or (actions & IAM_ADMIN_ACTIONS):
        # Only escalate to HVT identity mark for broad IAM (* or multiple privs)
        if "iam:*" in actions or len(actions & IAM_ADMIN_ACTIONS) >= 2:
            return {
                "kind": "iam-admin-actions",
                "reason": "Principal can create/modify IAM users, roles, or policies",
            }

    return None


def _add_privesc_to_outcome(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    src_id: str,
    outcome_id: str,
    outcome_type: str,
    provider: CloudProvider,
    reason: str,
    pattern_id: str,
    pattern_name: str,
) -> bool:
    for dst, rel, props in graph.adjacency.get(src_id, []):
        if (
            rel == "CAN_PRIVESC_TO"
            and dst == outcome_id
            and props.get("attack_outcome") == outcome_type
        ):
            return False
    meta = outcome_metadata(provider, outcome_type)
    builder.add_edge(
        src_id=src_id,
        rel_type="CAN_PRIVESC_TO",
        dst_id=outcome_id,
        props=enrichment_edge_props(
            source="high-value-catalog",
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            severity="critical",
            inferred=True,
            confidence="explicit",
            high_value_reason=reason,
            **meta,
        ),
    )
    return True


def _infer_provider(graph: GraphSnapshot) -> CloudProvider | None:
    for node in graph.nodes.values():
        raw = node.props.get("provider")
        if not raw:
            continue
        try:
            return CloudProvider(str(raw))
        except ValueError:
            continue
    return None
