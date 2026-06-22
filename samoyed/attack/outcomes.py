from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import CloudProvider

ADMIN_OUTCOME_TYPE = "administrator-access"
CLUSTER_ADMIN_OUTCOME_TYPE = "cluster-admin-access"
GCP_OWNER_OUTCOME_TYPE = "gcp-owner-access"
AZURE_OWNER_OUTCOME_TYPE = "azure-owner-access"


def admin_outcome_metadata(provider: CloudProvider) -> dict[str, Any]:
    if provider == CloudProvider.KUBERNETES:
        return {
            "attack_outcome": CLUSTER_ADMIN_OUTCOME_TYPE,
            "outcome_display": "Cluster-admin access",
            "outcome_concept": "AttackOutcome",
        }
    if provider == CloudProvider.GCP:
        return {
            "attack_outcome": GCP_OWNER_OUTCOME_TYPE,
            "outcome_display": "GCP Owner / project admin access",
            "outcome_concept": "AttackOutcome",
        }
    if provider == CloudProvider.AZURE:
        return {
            "attack_outcome": AZURE_OWNER_OUTCOME_TYPE,
            "outcome_display": "Azure Owner / subscription admin access",
            "outcome_concept": "AttackOutcome",
        }
    return {
        "attack_outcome": ADMIN_OUTCOME_TYPE,
        "outcome_display": "Administrator access",
        "outcome_concept": "AttackOutcome",
    }


def is_attack_outcome_edge(rel_type: str, props: dict[str, Any]) -> bool:
    return rel_type == "CAN_PRIVESC_TO" and bool(props.get("attack_outcome"))


def virtual_outcome_target(props: dict[str, Any], anchor_node_id: str) -> dict[str, Any]:
    return {
        "node_id": anchor_node_id,
        "concept_type": "AttackOutcome",
        "resource_type": props.get("attack_outcome"),
        "outcome_type": props.get("attack_outcome"),
        "outcome_display": props.get("outcome_display"),
        "virtual": True,
    }


def matches_attack_outcome_target(
    rel_type: str,
    edge_props: dict[str, Any],
    *,
    target_concept: str | None,
    target_resource_type: str | None,
) -> bool:
    if not is_attack_outcome_edge(rel_type, edge_props):
        return False
    if target_resource_type and edge_props.get("attack_outcome") != target_resource_type:
        return False
    if target_concept and target_concept not in {
        "AttackOutcome",
        edge_props.get("attack_outcome"),
        edge_props.get("outcome_concept"),
    }:
        return False
    return True
