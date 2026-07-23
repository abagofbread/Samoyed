from __future__ import annotations

import json
from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.capabilities import map_aws_action
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.connectors._shared import aws_scope, build_session_from_artifacts, parse_json_payload
from samoyed.graph.builder import GraphBuilder
from samoyed.policy.boundary import (
    boundary_arn_from_detail,
    permissions_boundary_props,
    resolve_boundary_actions_from_authz,
)


def import_aws_authz_details(
    payload: bytes | str,
    *,
    session_id: str,
    caller_arn: str | None = None,
    account_id: str | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    data = parse_json_payload(payload)
    if not isinstance(data, dict):
        raise ValueError("AWS authorization details must be a JSON object")

    account = str(
        account_id
        or data.get("account_id")
        or _account_from_details(data)
        or "unknown"
    )
    scope_id, scope_display = aws_scope(account)
    artifacts = list(_artifacts_from_authz(data, scope_id=scope_id))
    builder, meta = build_session_from_artifacts(
        artifacts,
        session_id=session_id,
        source="aws-authz-details",
        scope_id=scope_id,
        scope_display=scope_display,
        caller_arn=caller_arn,
        account_id=account,
    )
    meta["export_source"] = data.get("source", "aws:get-account-authorization-details")
    return builder, meta


def _account_from_details(data: dict[str, Any]) -> str | None:
    for user in data.get("UserDetailList") or []:
        arn = user.get("Arn", "")
        if "::" in arn:
            return arn.split(":")[5] if len(arn.split(":")) > 4 else None
    for role in data.get("RoleDetailList") or []:
        arn = role.get("Arn", "")
        parts = arn.split(":")
        if len(parts) > 4:
            return parts[4]
    return None


def _artifacts_from_authz(data: dict[str, Any], *, scope_id: str) -> Iterator[ConceptArtifact]:
    for user in data.get("UserDetailList") or []:
        arn = user.get("Arn")
        if not arn:
            continue
        edges: list[ConceptEdge] = []
        edges.extend(_inline_policies(user.get("UserPolicyList") or [], arn))
        edges.extend(_managed_policies(user.get("AttachedManagedPolicies") or [], arn, data))
        props: dict[str, Any] = {
            "native_kind": "User",
            "arn": arn,
            "name": user.get("UserName"),
            "display_name": user.get("UserName") or arn,
            "source": "aws-authz-details",
        }
        props.update(_boundary_props_for_detail(user, data))
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=arn,
            scope_id=scope_id,
            properties=props,
            evidence=Evidence("iam:GetAccountAuthorizationDetails.user", {"arn": arn}),
            edges=edges,
        )

    for role in data.get("RoleDetailList") or []:
        arn = role.get("Arn")
        if not arn:
            continue
        trust_doc = role.get("AssumeRolePolicyDocument") or {}
        edges = _trust_policy_edges(trust_doc, arn)
        edges.extend(_inline_policies(role.get("RolePolicyList") or [], arn))
        edges.extend(_managed_policies(role.get("AttachedManagedPolicies") or [], arn, data))
        props = {
            "native_kind": "Role",
            "arn": arn,
            "name": role.get("RoleName"),
            "display_name": role.get("RoleName") or arn,
            "source": "aws-authz-details",
            "assume_role_policy": trust_doc,
        }
        props.update(_boundary_props_for_detail(role, data))
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=arn,
            scope_id=scope_id,
            properties=props,
            evidence=Evidence("iam:GetAccountAuthorizationDetails.role", {"arn": arn}),
            edges=edges,
        )


def _boundary_props_for_detail(detail: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    arn = boundary_arn_from_detail(detail)
    if not arn:
        return {}
    actions = resolve_boundary_actions_from_authz(data, arn)
    return permissions_boundary_props(boundary_arn=arn, boundary_actions=actions or None)


def _trust_policy_edges(trust: Any, role_arn: str) -> list[ConceptEdge]:
    if isinstance(trust, str):
        trust = json.loads(trust)
    from samoyed.policy.irsa import is_oidc_provider_arn

    edges: list[ConceptEdge] = []
    for stmt in _statements(trust):
        if stmt.get("Effect") != "Allow":
            continue
        for principal in _principals(stmt.get("Principal")):
            if not principal.startswith("arn:"):
                continue
            # OIDC providers are not assume sources; IRSA repair uses Conditions.
            if is_oidc_provider_arn(principal):
                continue
            edges.append(
                ConceptEdge(
                    rel_type="CAN_ASSUME_ROLE",
                    src_native_id=principal,
                    target_native_id=role_arn,
                    props={"source": "aws-authz-details", "confidence": "explicit"},
                )
            )
    return edges


def _inline_policies(policies: list[dict[str, Any]], principal_arn: str) -> list[ConceptEdge]:
    edges: list[ConceptEdge] = []
    for pol in policies:
        doc = pol.get("PolicyDocument") or {}
        if isinstance(doc, str):
            doc = json.loads(doc)
        edges.extend(_statement_edges(doc, principal_arn, pol.get("PolicyName", "inline")))
    return edges


def _managed_policies(
    attached: list[dict[str, Any]],
    principal_arn: str,
    data: dict[str, Any],
) -> list[ConceptEdge]:
    by_arn = {p["Arn"]: p for p in data.get("Policies") or [] if p.get("Arn")}
    edges: list[ConceptEdge] = []
    for ref in attached:
        pol = by_arn.get(ref.get("PolicyArn", ""))
        if not pol:
            continue
        version_doc = (pol.get("PolicyVersionList") or [{}])[0].get("Document") or {}
        if isinstance(version_doc, str):
            version_doc = json.loads(version_doc)
        edges.extend(_statement_edges(version_doc, principal_arn, pol.get("PolicyName", "managed")))
    return edges


def _statement_edges(doc: dict[str, Any], principal_arn: str, policy_name: str) -> list[ConceptEdge]:
    edges: list[ConceptEdge] = []
    for stmt in _statements(doc):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        for action in actions:
            mapping = map_aws_action(str(action))
            if not mapping:
                continue
            rel = mapping.capability.value
            for resource in resources:
                target = _target_id(str(resource), mapping.resource_type)
                if ":role/" in str(resource) and str(action).startswith("sts:"):
                    rel = "CAN_ASSUME_ROLE"
                edges.append(
                    ConceptEdge(
                        rel_type=rel,
                        src_native_id=principal_arn,
                        target_native_id=target,
                        props={"action": action, "policy": policy_name, "source": "aws-authz-details"},
                    )
                )
    return edges


def _target_id(resource: str, resource_type: str | None) -> str:
    if resource.startswith("arn:aws:secretsmanager:"):
        return f"Secret:{resource}"
    if resource_type == "S3Bucket" or resource.startswith("arn:aws:s3:"):
        name = resource.replace("arn:aws:s3:::", "").split("/")[0].strip("*")
        return f"S3Bucket:{name}"
    if ":role/" in resource or ":user/" in resource:
        return resource
    return resource


def _statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement", [])
    if isinstance(stmt, dict):
        return [stmt]
    return list(stmt)


def _principals(principal: Any) -> list[str]:
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        out: list[str] = []
        for key in ("AWS", "Service", "Federated"):
            val = principal.get(key)
            if isinstance(val, str):
                out.append(val)
            elif isinstance(val, list):
                out.extend(str(v) for v in val)
        return out
    return [str(principal)]
