from __future__ import annotations

from typing import Any, Callable

from samoyed.graph.builder import GraphBuilder

ImportFn = Callable[..., tuple[GraphBuilder, dict[str, Any]]]

CONNECTORS: dict[str, dict[str, Any]] = {
    "iam-report": {
        "label": "IAM report (JSON)",
        "description": "Samoyed-compatible IAM JSON with identities, resources, and grants",
        "accept": ".json",
        "file_import": True,
    },
    "scoutsuite": {
        "label": "ScoutSuite",
        "description": "ScoutSuite results JSON (services.iam, s3, lambda)",
        "accept": ".json,.js",
        "file_import": True,
    },
    "cloudfox": {
        "label": "CloudFox",
        "description": "CloudFox findings export ({findings: [...]} or array)",
        "accept": ".json",
        "file_import": True,
    },
    "aws-authz-details": {
        "label": "AWS IAM authorization details",
        "description": "Raw output from iam:GetAccountAuthorizationDetails (PMapper, CloudMapper, aws cli)",
        "accept": ".json",
        "file_import": True,
    },
    "terraform": {
        "label": "Terraform state",
        "description": "Terraform tfstate JSON (VPC peering, SGs, EC2/Lambda placement)",
        "accept": ".tfstate,.json",
        "file_import": True,
    },
    "network-inventory": {
        "label": "Network inventory",
        "description": "Portable NetworkInventory JSON (placements, peerings, SG rules)",
        "accept": ".json",
        "file_import": True,
    },
    "cartography": {
        "label": "Cartography (Neo4j)",
        "description": "Live import from Cartography Neo4j — use API form fields, not file upload",
        "accept": "",
        "file_import": False,
    },
}


def list_connectors() -> list[dict[str, Any]]:
    return [{"id": key, **value} for key, value in CONNECTORS.items()]


def import_report(
    connector_id: str,
    payload: bytes | str,
    *,
    session_id: str,
    caller_arn: str | None = None,
    session_store: Any | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    if connector_id == "iam-report":
        from samoyed.connectors.iam_report.importer import import_iam_report

        return import_iam_report(
            payload, session_id=session_id, caller_arn=caller_arn, session_store=session_store
        )
    if connector_id == "scoutsuite":
        from samoyed.connectors.scoutsuite.importer import import_scoutsuite_report

        return import_scoutsuite_report(payload, session_id=session_id, caller_arn=caller_arn)
    if connector_id == "cloudfox":
        from samoyed.connectors.cloudfox.importer import import_cloudfox_report

        return import_cloudfox_report(payload, session_id=session_id, caller_arn=caller_arn)
    if connector_id == "aws-authz-details":
        from samoyed.connectors.aws_authz.importer import import_aws_authz_details

        return import_aws_authz_details(payload, session_id=session_id, caller_arn=caller_arn)
    if connector_id == "terraform":
        from samoyed.connectors.terraform.importer import import_terraform

        return import_terraform(
            payload, session_id=session_id, caller_arn=caller_arn, session_store=session_store
        )
    if connector_id == "network-inventory":
        from samoyed.connectors.network_inventory.importer import import_network_inventory

        return import_network_inventory(
            payload, session_id=session_id, caller_arn=caller_arn, session_store=session_store
        )
    raise ValueError(f"Unknown connector: {connector_id}")
