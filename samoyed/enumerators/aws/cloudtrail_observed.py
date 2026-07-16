"""Optional CloudTrail observed-usage edges (GetSecretValue, GetObject, Decrypt).

Gated by ``SAMOYED_CLOUDTRAIL_OBSERVED=1`` — LookupEvents is chatty and capped.
Emits READS/CONTROLS with ``discovered_via: cloudtrail`` for principals that
actually touched resources (fills gaps config + IAM cannot see).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.contracts import ConceptEnumerator
from samoyed.enumerators.runner import paginate_call
from samoyed.graph.resource_scope import resolve_policy_resource

# EventName → (rel_type, resource_type_hint)
_OBSERVED_EVENTS: dict[str, tuple[str, str | None]] = {
    "GetSecretValue": ("READS", "Secret"),
    "BatchGetSecretValue": ("READS", "Secret"),
    "GetParameter": ("READS", "SSMParameter"),
    "GetParameters": ("READS", "SSMParameter"),
    "GetParametersByPath": ("READS", "SSMParameter"),
    "GetObject": ("READS", "S3Bucket"),
    "GetObjectAcl": ("READS", "S3Bucket"),
    "Decrypt": ("CONTROLS", "KMSKey"),
    "GenerateDataKey": ("CONTROLS", "KMSKey"),
}


def cloudtrail_observed_enabled(ctx: EnumContext | None = None) -> bool:
    if os.environ.get("SAMOYED_CLOUDTRAIL_OBSERVED", "").strip().lower() in {"1", "true", "yes"}:
        return True
    if ctx and ctx.scope.properties.get("cloudtrail_observed"):
        return True
    return False


class AwsCloudTrailObservedEnumerator:
    concept = ConceptType.SECRET_STORE
    name = "aws-cloudtrail-observed"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        if not cloudtrail_observed_enabled(ctx):
            return

        cred = ctx.credentials
        ct = cred.client("cloudtrail")  # type: ignore[attr-defined]
        lookback_days = int(os.environ.get("SAMOYED_CLOUDTRAIL_LOOKBACK_DAYS", "7"))
        max_events = int(os.environ.get("SAMOYED_CLOUDTRAIL_MAX_EVENTS", "200"))
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=lookback_days)

        emitted = 0
        seen_edges: set[tuple[str, str, str]] = set()

        for event_name, (rel, rtype_hint) in _OBSERVED_EVENTS.items():
            if emitted >= max_events:
                break
            resp = paginate_call(
                ctx,
                operation="cloudtrail:LookupEvents",
                call=lambda en=event_name: ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": en}],
                    StartTime=start,
                    EndTime=end,
                    MaxResults=min(50, max_events - emitted),
                ),
            )
            if not resp:
                continue
            for evt in resp.get("Events", []):
                if emitted >= max_events:
                    break
                for art in _artifacts_from_event(ctx, evt, rel=rel, rtype_hint=rtype_hint, seen=seen_edges):
                    yield art
                    emitted += 1


def _artifacts_from_event(
    ctx: EnumContext,
    evt: dict[str, Any],
    *,
    rel: str,
    rtype_hint: str | None,
    seen: set[tuple[str, str, str]],
) -> Iterator[ConceptArtifact]:
    principal = _principal_from_event(evt)
    resource_arn = _resource_from_event(evt, rtype_hint)
    if not principal or not resource_arn:
        return

    native_id, _ = resolve_policy_resource(resource_arn, rtype_hint)
    key = (principal, rel, native_id)
    if key in seen:
        return
    seen.add(key)

    concept = ConceptType.SECRET_STORE
    if rtype_hint == "S3Bucket":
        concept = ConceptType.DATA_STORE
    elif rtype_hint == "KMSKey":
        concept = ConceptType.DATA_STORE
    elif rtype_hint == "SSMParameter":
        concept = ConceptType.SECRET_STORE

    yield ConceptArtifact(
        concept_type=ConceptType.IDENTITY,
        provider=CloudProvider.AWS,
        native_id=principal,
        scope_id=ctx.scope.scope_id,
        properties={
            "arn": principal,
            "discovered_via": "cloudtrail",
            "native_kind": "Role" if ":role/" in principal else "User" if ":user/" in principal else "Principal",
        },
        evidence=Evidence("cloudtrail:LookupEvents", {"event": evt.get("EventName"), "principal": principal}),
        confidence=ConfidenceType.EXPLICIT,
    )

    yield ConceptArtifact(
        concept_type=concept,
        provider=CloudProvider.AWS,
        native_id=native_id,
        scope_id=ctx.scope.scope_id,
        properties={
            "resource_type": rtype_hint or "Unknown",
            "arn": resource_arn if resource_arn.startswith("arn:") else None,
            "discovered_via": "cloudtrail",
        },
        evidence=Evidence(
            "cloudtrail:LookupEvents",
            {
                "event": evt.get("EventName"),
                "event_time": str(evt.get("EventTime")),
                "principal": principal,
                "resource": resource_arn,
            },
        ),
        confidence=ConfidenceType.EXPLICIT,
        edges=[
            ConceptEdge(
                rel_type=rel,
                src_native_id=principal,
                target_native_id=native_id,
                target_concept_type=concept,
                props={
                    "resource": resource_arn,
                    "resource_type": rtype_hint or "Unknown",
                    "action": evt.get("EventName"),
                    "source": "cloudtrail",
                    "discovered_via": "cloudtrail",
                    "event_time": str(evt.get("EventTime") or ""),
                },
                confidence=ConfidenceType.EXPLICIT,
            )
        ],
    )


def _principal_from_event(evt: dict[str, Any]) -> str | None:
    # CloudTrail LookupEvents flattens Username; CloudTrailEvent JSON has userIdentity
    raw = evt.get("CloudTrailEvent")
    if isinstance(raw, str):
        import json

        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {}
        uid = body.get("userIdentity") or {}
        for key in ("arn", "principalId"):
            if uid.get(key) and str(uid[key]).startswith("arn:"):
                return str(uid["arn"]) if key == "arn" else None
        if uid.get("arn"):
            return str(uid["arn"])
        if uid.get("type") == "AWSService":
            return None
        session = uid.get("sessionContext") or {}
        issuer = (session.get("sessionIssuer") or {}).get("arn")
        if issuer:
            return str(issuer)
    username = evt.get("Username")
    if isinstance(username, str) and username.startswith("arn:"):
        return username
    return None


def _resource_from_event(evt: dict[str, Any], rtype_hint: str | None) -> str | None:
    resources = evt.get("Resources") or []
    for res in resources:
        name = res.get("ResourceName") or res.get("ResourceArn")
        if name:
            return str(name)
    raw = evt.get("CloudTrailEvent")
    if isinstance(raw, str):
        import json

        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            return None
        # requestParameters often carries SecretId / bucketName / keyId
        rp = body.get("requestParameters") or {}
        if rtype_hint == "Secret" and rp.get("secretId"):
            return str(rp["secretId"])
        if rtype_hint == "SSMParameter" and rp.get("name"):
            return str(rp["name"]) if str(rp["name"]).startswith("arn:") else f"arn:aws:ssm:::parameter{rp['name']}"
        if rtype_hint == "S3Bucket" and rp.get("bucketName"):
            return f"arn:aws:s3:::{rp['bucketName']}"
        if rtype_hint == "KMSKey" and (rp.get("keyId") or rp.get("KeyId")):
            return str(rp.get("keyId") or rp.get("KeyId"))
        for r in body.get("resources") or []:
            if r.get("ARN"):
                return str(r["ARN"])
    return None
