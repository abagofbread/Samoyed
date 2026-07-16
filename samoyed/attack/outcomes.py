from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import CloudProvider

ADMIN_OUTCOME_TYPE = "administrator-access"
IAM_ADMIN_OUTCOME_TYPE = "iam-administration"
ACCOUNT_ROOT_OUTCOME_TYPE = "account-root-access"
CLUSTER_ADMIN_OUTCOME_TYPE = "cluster-admin-access"
GCP_OWNER_OUTCOME_TYPE = "gcp-owner-access"
AZURE_OWNER_OUTCOME_TYPE = "azure-owner-access"

# SkyArk AWStealth service-scoped privilege types (not full account admin).
S3_ADMIN_OUTCOME_TYPE = "full-s3-admin"
KMS_ADMIN_OUTCOME_TYPE = "full-kms-admin"
EC2_ADMIN_OUTCOME_TYPE = "full-ec2-admin"
STS_ADMIN_OUTCOME_TYPE = "full-sts-admin"
CLOUDFORMATION_ADMIN_OUTCOME_TYPE = "full-cloudformation-admin"
LAMBDA_ADMIN_OUTCOME_TYPE = "full-lambda-admin"

SERVICE_ADMIN_OUTCOME_TYPES: tuple[str, ...] = (
    S3_ADMIN_OUTCOME_TYPE,
    KMS_ADMIN_OUTCOME_TYPE,
    EC2_ADMIN_OUTCOME_TYPE,
    STS_ADMIN_OUTCOME_TYPE,
    CLOUDFORMATION_ADMIN_OUTCOME_TYPE,
    LAMBDA_ADMIN_OUTCOME_TYPE,
)

# Blatant crown-jewel outcomes auto-materialised as high-value nodes.
BLATANT_OUTCOME_TYPES: tuple[str, ...] = (
    ADMIN_OUTCOME_TYPE,
    IAM_ADMIN_OUTCOME_TYPE,
    ACCOUNT_ROOT_OUTCOME_TYPE,
    *SERVICE_ADMIN_OUTCOME_TYPES,
)

_OUTCOME_DISPLAY: dict[str, str] = {
    ADMIN_OUTCOME_TYPE: "Administrator access",
    IAM_ADMIN_OUTCOME_TYPE: "IAM administration (modify users/roles/policies)",
    ACCOUNT_ROOT_OUTCOME_TYPE: "AWS account root",
    CLUSTER_ADMIN_OUTCOME_TYPE: "Cluster-admin access",
    GCP_OWNER_OUTCOME_TYPE: "GCP Owner / project admin access",
    AZURE_OWNER_OUTCOME_TYPE: "Azure Owner / subscription admin access",
    S3_ADMIN_OUTCOME_TYPE: "Full S3 administration (s3:* on *)",
    KMS_ADMIN_OUTCOME_TYPE: "Full KMS administration (kms:* on *)",
    EC2_ADMIN_OUTCOME_TYPE: "Full EC2 administration (ec2:* on *)",
    STS_ADMIN_OUTCOME_TYPE: "Full STS administration (sts:* on *)",
    CLOUDFORMATION_ADMIN_OUTCOME_TYPE: "Full CloudFormation administration (cloudformation:* on *)",
    LAMBDA_ADMIN_OUTCOME_TYPE: "Full Lambda administration (lambda:* on *)",
}


def outcome_metadata(provider: CloudProvider, outcome_type: str) -> dict[str, Any]:
    """Metadata for a specific AttackOutcome type."""
    display = _OUTCOME_DISPLAY.get(outcome_type)
    if not display:
        display = outcome_type.replace("-", " ").title()
    return {
        "attack_outcome": outcome_type,
        "outcome_display": display,
        "outcome_concept": "AttackOutcome",
        "provider": provider.value,
    }


def admin_outcome_metadata(provider: CloudProvider) -> dict[str, Any]:
    if provider == CloudProvider.KUBERNETES:
        return outcome_metadata(provider, CLUSTER_ADMIN_OUTCOME_TYPE)
    if provider == CloudProvider.GCP:
        return outcome_metadata(provider, GCP_OWNER_OUTCOME_TYPE)
    if provider == CloudProvider.AZURE:
        return outcome_metadata(provider, AZURE_OWNER_OUTCOME_TYPE)
    return outcome_metadata(provider, ADMIN_OUTCOME_TYPE)


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
