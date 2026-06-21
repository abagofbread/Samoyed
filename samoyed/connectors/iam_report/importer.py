from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.connectors._shared import aws_scope, build_session_from_artifacts, parse_json_payload
from samoyed.graph.builder import GraphBuilder

CONCEPT_MAP = {
    "Identity": ConceptType.IDENTITY,
    "DataStore": ConceptType.DATA_STORE,
    "SecretStore": ConceptType.SECRET_STORE,
    "RuntimeBinding": ConceptType.RUNTIME_BINDING,
    "Entitlement": ConceptType.ENTITLEMENT,
    "Trust": ConceptType.TRUST,
    "ManagementEndpoint": ConceptType.MANAGEMENT_ENDPOINT,
}


def import_iam_report(
    payload: bytes | str,
    *,
    session_id: str,
    caller_arn: str | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    data = parse_json_payload(payload)
    if not isinstance(data, dict):
        raise ValueError("IAM report must be a JSON object")

    account_id = str(data.get("account_id") or data.get("account") or "unknown")
    scope_id, scope_display = aws_scope(account_id)
    artifacts = list(_artifacts_from_report(data, scope_id=scope_id, account_id=account_id))
    resolved_caller = caller_arn or data.get("caller_arn")
    builder, meta = build_session_from_artifacts(
        artifacts,
        session_id=session_id,
        source="iam-report",
        scope_id=scope_id,
        scope_display=scope_display,
        caller_arn=resolved_caller,
        account_id=account_id,
    )
    return builder, meta


def _artifacts_from_report(
    data: dict[str, Any],
    *,
    scope_id: str,
    account_id: str,
) -> Iterator[ConceptArtifact]:
    for identity in data.get("identities") or []:
        arn = identity.get("arn") or identity.get("id")
        if not arn:
            continue
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=arn,
            scope_id=scope_id,
            properties={
                "native_kind": identity.get("kind") or _kind_from_arn(arn),
                "arn": arn,
                "name": identity.get("name"),
                "display_name": identity.get("display_name") or identity.get("name") or arn,
                "source": "iam-report",
            },
            evidence=Evidence("iam-report:identity", {"arn": arn}),
            edges=_grants_for(data, from_id=arn),
        )

    for resource in data.get("resources") or []:
        native_id = resource.get("id") or resource.get("native_id")
        if not native_id:
            continue
        concept_name = resource.get("concept") or resource.get("concept_type") or "DataStore"
        concept = CONCEPT_MAP.get(concept_name, ConceptType.DATA_STORE)
        yield ConceptArtifact(
            concept_type=concept,
            provider=CloudProvider.AWS,
            native_id=native_id,
            scope_id=scope_id,
            properties={
                "resource_type": resource.get("type") or resource.get("resource_type"),
                "name": resource.get("name"),
                "display_name": resource.get("display_name") or resource.get("name") or native_id,
                "source": "iam-report",
            },
            evidence=Evidence("iam-report:resource", {"id": native_id}),
        )

    if not data.get("identities") and data.get("grants"):
        for grant in data["grants"]:
            src = grant.get("from")
            if not src:
                continue
            yield ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=CloudProvider.AWS,
                native_id=src,
                scope_id=scope_id,
                properties={
                    "native_kind": _kind_from_arn(src),
                    "arn": src if src.startswith("arn:") else None,
                    "display_name": src,
                    "source": "iam-report",
                },
                evidence=Evidence("iam-report:grant-src", {"from": src}),
                edges=[_grant_edge(grant)],
            )


def _grants_for(data: dict[str, Any], from_id: str) -> list[ConceptEdge]:
    edges: list[ConceptEdge] = []
    for grant in data.get("grants") or []:
        if grant.get("from") != from_id:
            continue
        edges.append(_grant_edge(grant))
    return edges


def _grant_edge(grant: dict[str, Any]) -> ConceptEdge:
    rel = grant.get("rel") or grant.get("relationship") or "READS"
    target = grant.get("to") or grant.get("target")
    props = {k: v for k, v in grant.items() if k not in {"from", "to", "rel", "relationship", "target"}}
    if grant.get("action"):
        props["action"] = grant["action"]
    props["source"] = "iam-report"
    return ConceptEdge(rel_type=rel, target_native_id=target or "", props=props)


def _kind_from_arn(arn: str) -> str:
    if ":role/" in arn:
        return "Role"
    if ":user/" in arn:
        return "User"
    return "Identity"
