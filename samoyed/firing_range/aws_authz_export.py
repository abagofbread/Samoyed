from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import boto3


def export_account_authorization_details(
    *,
    endpoint_url: str,
    region: str,
    access_key: str,
    secret_key: str,
) -> dict[str, Any]:
    """Call AWS IAM get_account_authorization_details (real API used by PMapper, CloudMapper, etc.)."""
    iam = boto3.client(
        "iam",
        endpoint_url=endpoint_url,
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )
    payload: dict[str, Any] = {
        "source": "aws:get-account-authorization-details",
        "endpoint": endpoint_url,
        "region": region,
    }
    for key in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"):
        payload[key] = []
    marker: str | None = None
    while True:
        kwargs: dict[str, Any] = {"Filter": ["Role", "User", "Group", "LocalManagedPolicy"]}
        if marker:
            kwargs["Marker"] = marker
        resp = iam.get_account_authorization_details(**kwargs)
        for key in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"):
            payload[key].extend(resp.get(key, []))
        if not resp.get("IsTruncated"):
            break
        marker = resp.get("Marker")
    return _json_safe(payload)


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value
