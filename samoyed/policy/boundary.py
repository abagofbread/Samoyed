"""IAM permissions boundary helpers.

Boundaries are a *ceiling* on effective permissions (identity ∩ boundary). We store
them as Identity node properties — no CONSTRAINED_BY (or similar) edges, which would
be noisy and redundant with analyzer clamping.
"""

from __future__ import annotations

import json
from typing import Any


def actions_from_policy_document(doc: Any) -> list[str]:
    """Collect Allow-statement actions from a policy document (boundary ceiling)."""
    if isinstance(doc, str):
        doc = json.loads(doc)
    if not isinstance(doc, dict):
        return []
    actions: list[str] = []
    for stmt in _statements(doc):
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        for action in raw:
            if action:
                actions.append(str(action))
    return list(dict.fromkeys(actions))


def permissions_boundary_props(
    *,
    boundary_arn: str | None,
    boundary_actions: list[str] | None = None,
) -> dict[str, Any]:
    """Props to merge onto an Identity node. Empty dict when no boundary."""
    if not boundary_arn and not boundary_actions:
        return {}
    props: dict[str, Any] = {}
    if boundary_arn:
        props["permissions_boundary_arn"] = boundary_arn
    if boundary_actions:
        props["permissions_boundary_actions"] = list(dict.fromkeys(str(a) for a in boundary_actions))
    return props


def boundary_arn_from_detail(detail: dict[str, Any]) -> str | None:
    """Extract boundary ARN from GetAccountAuthorizationDetails user/role detail."""
    pb = detail.get("PermissionsBoundary") or {}
    if isinstance(pb, dict):
        arn = pb.get("PermissionsBoundaryArn") or pb.get("permissionsBoundaryArn")
        if arn:
            return str(arn)
    arn = detail.get("PermissionsBoundaryArn")
    return str(arn) if arn else None


def resolve_boundary_actions_from_authz(
    data: dict[str, Any],
    boundary_arn: str,
) -> list[str]:
    """Find the boundary managed policy document inside an authz-details export."""
    for pol in data.get("Policies") or []:
        if pol.get("Arn") != boundary_arn:
            continue
        versions = pol.get("PolicyVersionList") or []
        doc = None
        for version in versions:
            if version.get("IsDefaultVersion"):
                doc = version.get("Document")
                break
        if doc is None and versions:
            doc = versions[0].get("Document")
        return actions_from_policy_document(doc)
    return []


def _statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement", [])
    if isinstance(stmt, dict):
        return [stmt]
    return list(stmt)
