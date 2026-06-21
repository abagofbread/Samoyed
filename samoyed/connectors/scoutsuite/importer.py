from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.connectors._shared import aws_scope, build_session_from_artifacts, parse_json_payload
from samoyed.graph.builder import GraphBuilder


def import_scoutsuite_report(
    payload: bytes | str,
    *,
    session_id: str,
    caller_arn: str | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    data = parse_json_payload(payload)
    if not isinstance(data, dict):
        raise ValueError("ScoutSuite report must be a JSON object")

    account_id = str(
        data.get("account_id")
        or data.get("aws_account_id")
        or _deep_get(data, "services", "iam", "account_id")
        or "unknown"
    )
    scope_id, scope_display = aws_scope(account_id)
    artifacts = list(_artifacts_from_scoutsuite(data, scope_id=scope_id))
    builder, meta = build_session_from_artifacts(
        artifacts,
        session_id=session_id,
        source="scoutsuite",
        scope_id=scope_id,
        scope_display=scope_display,
        caller_arn=caller_arn,
        account_id=account_id,
    )
    return builder, meta


def _artifacts_from_scoutsuite(data: dict[str, Any], *, scope_id: str) -> Iterator[ConceptArtifact]:
    services = data.get("services") or {}
    iam = services.get("iam") or {}

    for section, kind in (("users", "User"), ("roles", "Role")):
        items = iam.get(section) or {}
        if isinstance(items, list):
            items = {item.get("name", str(i)): item for i, item in enumerate(items)}
        for name, item in items.items():
            if not isinstance(item, dict):
                continue
            arn = item.get("arn") or item.get("id")
            if not arn:
                continue
            edges = _iam_policy_edges(item, arn)
            edges.extend(_trust_edges(item, arn))
            yield ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=CloudProvider.AWS,
                native_id=arn,
                scope_id=scope_id,
                properties={
                    "native_kind": kind,
                    "arn": arn,
                    "name": name,
                    "display_name": name,
                    "source": "scoutsuite",
                },
                evidence=Evidence("scoutsuite:iam", {"arn": arn, "section": section}),
                edges=edges,
            )

    s3 = services.get("s3") or {}
    buckets = s3.get("buckets") or {}
    if isinstance(buckets, list):
        buckets = {b.get("name", str(i)): b for i, b in enumerate(buckets)}
    for name, bucket in buckets.items():
        native_id = f"S3Bucket:{name}"
        yield ConceptArtifact(
            concept_type=ConceptType.DATA_STORE,
            provider=CloudProvider.AWS,
            native_id=native_id,
            scope_id=scope_id,
            properties={
                "resource_type": "S3Bucket",
                "bucket_name": name,
                "display_name": name,
                "source": "scoutsuite",
            },
            evidence=Evidence("scoutsuite:s3", {"bucket": name, "details": bucket if isinstance(bucket, dict) else {}}),
        )

    lam = services.get("lambda") or services.get("awslambda") or {}
    functions = lam.get("functions") or {}
    if isinstance(functions, list):
        functions = {f.get("name", str(i)): f for i, f in enumerate(functions)}
    for name, fn in functions.items():
        if not isinstance(fn, dict):
            continue
        fn_arn = fn.get("arn") or f"arn:aws:lambda:us-east-1:000000000000:function:{name}"
        role_arn = fn.get("role") or fn.get("execution_role_arn")
        edges: list[ConceptEdge] = []
        if role_arn:
            edges.append(
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=role_arn,
                    props={"source": "scoutsuite", "execution_role_arn": role_arn},
                )
            )
        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id=f"LambdaFunction:{fn_arn}",
            scope_id=scope_id,
            properties={
                "resource_type": "LambdaFunction",
                "function_name": name,
                "arn": fn_arn,
                "source": "scoutsuite",
            },
            evidence=Evidence("scoutsuite:lambda", {"function": name}),
            edges=edges,
        )


def _iam_policy_edges(item: dict[str, Any], principal_arn: str) -> list[ConceptEdge]:
    edges: list[ConceptEdge] = []
    for policy in _iter_policies(item):
        for action in policy.get("actions") or policy.get("Action") or []:
            if isinstance(action, str):
                actions = [action]
            else:
                actions = list(action)
            for act in actions:
                if act in ("*", "*:*") or act.startswith("s3:"):
                    edges.append(
                        ConceptEdge(
                            rel_type="READS" if "Get" in act or act == "s3:*" else "CONTROLS",
                            target_native_id=f"S3Bucket:{policy.get('resource', '*')}",
                            props={"action": act, "source": "scoutsuite"},
                        )
                    )
                if act.startswith("secretsmanager:"):
                    edges.append(
                        ConceptEdge(
                            rel_type="READS",
                            target_native_id=f"Secret:{policy.get('resource', 'unknown')}",
                            props={"action": act, "source": "scoutsuite"},
                        )
                    )
                if act.startswith("iam:PassRole") or act.startswith("lambda:"):
                    edges.append(
                        ConceptEdge(
                            rel_type="CONTROLS",
                            target_native_id=policy.get("resource") or principal_arn,
                            props={"action": act, "source": "scoutsuite"},
                        )
                    )
    return edges


def _trust_edges(item: dict[str, Any], role_arn: str) -> list[ConceptEdge]:
    edges: list[ConceptEdge] = []
    trust = item.get("trust_policy") or item.get("assume_role_policy") or {}
    statements = trust.get("Statement") or trust.get("statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        for principal in _statement_principals(stmt):
            edges.append(
                ConceptEdge(
                    rel_type="CAN_ASSUME_ROLE",
                    src_native_id=principal,
                    target_native_id=role_arn,
                    props={"source": "scoutsuite", "confidence": "explicit"},
                )
            )
    return edges


def _statement_principals(stmt: dict[str, Any]) -> list[str]:
    principal = stmt.get("Principal") or {}
    if isinstance(principal, str):
        return [principal]
    out: list[str] = []
    for key in ("AWS", "Service", "Federated"):
        val = principal.get(key)
        if isinstance(val, str):
            out.append(val)
        elif isinstance(val, list):
            out.extend(str(v) for v in val)
    return out


def _iter_policies(item: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for key in ("policies", "inline_policies", "attached_policies"):
        block = item.get(key) or {}
        if isinstance(block, dict):
            for pol in block.values():
                if isinstance(pol, dict):
                    yield pol
        elif isinstance(block, list):
            for pol in block:
                if isinstance(pol, dict):
                    yield pol


def _deep_get(data: dict[str, Any], *keys: str) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur
