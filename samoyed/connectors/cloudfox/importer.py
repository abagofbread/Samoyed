from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.connectors._shared import aws_scope, build_session_from_artifacts, parse_json_payload
from samoyed.graph.builder import GraphBuilder

REL_MAP = {
    "reads": "READS",
    "read": "READS",
    "writes": "WRITES",
    "write": "WRITES",
    "controls": "CONTROLS",
    "control": "CONTROLS",
    "assume": "CAN_ASSUME_ROLE",
    "assume_role": "CAN_ASSUME_ROLE",
    "executes_as": "EXECUTES_AS",
    "executes": "EXECUTES_AS",
}


def import_cloudfox_report(
    payload: bytes | str,
    *,
    session_id: str,
    caller_arn: str | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    data = parse_json_payload(payload)
    account_id = "unknown"
    if isinstance(data, dict):
        account_id = str(data.get("account") or data.get("account_id") or "unknown")
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        account_id = str(data[0].get("account") or data[0].get("account_id") or "unknown")

    scope_id, scope_display = aws_scope(account_id)
    artifacts = list(_artifacts_from_cloudfox(data, scope_id=scope_id))
    builder, meta = build_session_from_artifacts(
        artifacts,
        session_id=session_id,
        source="cloudfox",
        scope_id=scope_id,
        scope_display=scope_display,
        caller_arn=caller_arn,
        account_id=account_id,
    )
    return builder, meta


def _artifacts_from_cloudfox(data: Any, *, scope_id: str) -> Iterator[ConceptArtifact]:
    findings = _normalize_findings(data)
    principals: dict[str, list[ConceptEdge]] = {}

    for finding in findings:
        principal = finding.get("principal") or finding.get("identity") or finding.get("from")
        target = finding.get("resource") or finding.get("target") or finding.get("to")
        if not principal:
            continue
        rel = _map_rel(finding.get("capability") or finding.get("rel") or finding.get("relationship"))
        props = {"source": "cloudfox"}
        if finding.get("action"):
            props["action"] = finding["action"]
        if finding.get("description"):
            props["description"] = finding["description"]
        if target:
            principals.setdefault(principal, []).append(
                ConceptEdge(rel_type=rel, target_native_id=target, props=props)
            )

        if target and _looks_like_resource(target):
            yield ConceptArtifact(
                concept_type=_concept_for_target(target),
                provider=CloudProvider.AWS,
                native_id=target,
                scope_id=scope_id,
                properties={
                    "resource_type": _resource_type(target),
                    "display_name": target,
                    "source": "cloudfox",
                },
                evidence=Evidence("cloudfox:resource", {"target": target}),
            )

    for principal, edges in principals.items():
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=principal,
            scope_id=scope_id,
            properties={
                "native_kind": "Role" if ":role/" in principal else "User" if ":user/" in principal else "Identity",
                "arn": principal if principal.startswith("arn:") else None,
                "display_name": principal,
                "source": "cloudfox",
            },
            evidence=Evidence("cloudfox:principal", {"principal": principal}),
            edges=edges,
        )


def _normalize_findings(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("findings"), list):
            return [item for item in data["findings"] if isinstance(item, dict)]
        if isinstance(data.get("results"), list):
            return [item for item in data["results"] if isinstance(item, dict)]
    raise ValueError("CloudFox report must be a findings list or {findings: [...]} object")


def _map_rel(raw: Any) -> str:
    if not raw:
        return "READS"
    key = str(raw).strip().lower().replace("-", "_")
    return REL_MAP.get(key, str(raw).upper())


def _looks_like_resource(target: str) -> bool:
    return target.startswith("S3Bucket:") or target.startswith("Secret:") or target.startswith("LambdaFunction:")


def _concept_for_target(target: str) -> ConceptType:
    if target.startswith("Secret:"):
        return ConceptType.SECRET_STORE
    if target.startswith("LambdaFunction:"):
        return ConceptType.RUNTIME_BINDING
    return ConceptType.DATA_STORE


def _resource_type(target: str) -> str:
    if target.startswith("Secret:"):
        return "Secret"
    if target.startswith("LambdaFunction:"):
        return "LambdaFunction"
    if target.startswith("S3Bucket:"):
        return "S3Bucket"
    return "Resource"
