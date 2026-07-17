"""Resource scope normalization and intersection for resource-mediated pivots.

Matches IAM policy Resource strings against inventory/consumer refs so that
principal WRITES/CONTROLS scopes can connect to workloads that USE/READ the
intersecting subset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


PRODUCER_RELS = frozenset({"WRITES", "CONTROLS", "DELETES"})
CONSUMER_RELS = frozenset({"READS", "USES_IMAGE", "PULLS_FROM", "DEPENDS_ON"})


@dataclass(frozen=True)
class ResourceScope:
    """A concrete or patterned resource reference."""

    family: str  # s3 | secretsmanager | ecr | ssm | other
    resource_type: str  # S3Bucket | Secret | ECRRepository | SSMParameter | …
    canonical_id: str  # inventory-style native id when known
    pattern: str  # IAM-style ARN/pattern or concrete ARN/name
    path_prefix: str | None = None  # S3 key / SSM path prefix (no leading bucket)
    image_tag: str | None = None  # ECR image tag if known

    @property
    def is_wildcard(self) -> bool:
        return "*" in self.pattern or self.pattern.endswith(":*") or self.canonical_id.endswith(":*")


@dataclass(frozen=True)
class ScopeIntersection:
    scope: ResourceScope
    match_kind: str  # exact | arn_match | prefix | type_wildcard
    confidence: str  # explicit | wildcard | unknown-conditions


_ECR_URI_RE = re.compile(
    r"^(?P<account>\d+)\.dkr\.ecr\.(?P<region>[a-z0-9-]+)\.amazonaws\.com/"
    r"(?P<repo>[^:@]+)(?::(?P<tag>[^@]+))?(?:@(?P<digest>.+))?$"
)
_S3_ARN_RE = re.compile(r"^arn:aws:s3:::(?P<bucket>[^/]+)(?:/(?P<key>.*))?$")
_ECR_ARN_RE = re.compile(
    r"^arn:aws:ecr:(?P<region>[^:]+):(?P<account>\d+):repository/(?P<repo>.+)$"
)
_SSM_ARN_RE = re.compile(
    r"^arn:aws:ssm:(?P<region>[^:]*):(?P<account>[^:]*):parameter/(?P<path>.+)$"
)


def resolve_policy_resource(resource: str, resource_type: str | None) -> tuple[str, ResourceScope]:
    """Map an IAM Resource string to (native_id, scope) for graph targeting."""
    resource = (resource or "").strip()
    rtype = resource_type or "UnresolvedResource"

    if resource == "*":
        scope = ResourceScope(
            family=_family_for_type(rtype),
            resource_type=rtype,
            canonical_id=f"{rtype}:*",
            pattern="*",
        )
        return scope.canonical_id, scope

    typed_prefixes = {
        "S3Bucket",
        "Secret",
        "ECRRepository",
        "SSMParameter",
        "LambdaFunction",
        "EC2Instance",
    }
    if ":" in resource and not resource.startswith("arn:") and resource.split(":", 1)[0] in typed_prefixes:
        typed, rest = resource.split(":", 1)
        return _scope_from_typed(typed, rest)

    if resource.startswith("arn:aws:s3:::") or resource.startswith("arn:aws:s3:"):
        return _scope_from_s3(resource)

    if resource.startswith("arn:aws:secretsmanager:"):
        return _scope_from_secretsmanager(resource)

    if resource.startswith("arn:aws:ecr:") and ":repository/" in resource:
        return _scope_from_ecr_arn(resource)

    if resource.startswith("arn:aws:ssm:") and ":parameter" in resource:
        return _scope_from_ssm(resource)

    if rtype == "S3Bucket":
        name = resource.strip("*").split("/")[0] or "*"
        if name == "*" or not name:
            nid = "S3Bucket:*"
            scope = ResourceScope("s3", "S3Bucket", nid, resource)
            return nid, scope
        key = None
        cleaned = resource.strip("*")
        if "/" in cleaned:
            key = cleaned.split("/", 1)[1]
        nid = f"S3Bucket:{name}"
        return nid, ResourceScope("s3", "S3Bucket", nid, resource, path_prefix=key or None)

    if rtype == "Secret":
        nid = f"Secret:{resource}"
        return nid, ResourceScope("secretsmanager", "Secret", nid, resource)

    if rtype == "ECRRepository":
        nid = f"ECRRepository:{resource}"
        return nid, ResourceScope("ecr", "ECRRepository", nid, resource)

    if rtype == "SSMParameter":
        path = resource if resource.startswith("/") else f"/{resource}"
        nid = f"SSMParameter:{path.lstrip('/')}"
        return nid, ResourceScope("ssm", "SSMParameter", nid, resource, path_prefix=path)

    nid = f"{rtype}:{resource}"
    return nid, ResourceScope("other", rtype, nid, resource)


def scope_from_native_id(native_id: str, *, image_uri: str | None = None) -> ResourceScope | None:
    """Build a scope from an inventory or typed native id."""
    if not native_id:
        return None
    if image_uri or native_id.startswith(("aws:ecs:image:", "kubernetes:image:")):
        uri = image_uri or native_id.split(":", 2)[-1]
        parsed = parse_ecr_image_uri(uri)
        if parsed:
            return parsed
        return ResourceScope("other", "Image", native_id, uri or native_id)

    if native_id.startswith("S3Bucket:"):
        return _scope_from_typed("S3Bucket", native_id.split(":", 1)[1])[1]
    if native_id.startswith("Secret:"):
        return _scope_from_typed("Secret", native_id.split(":", 1)[1])[1]
    if native_id.startswith("ECRRepository:"):
        return _scope_from_typed("ECRRepository", native_id.split(":", 1)[1])[1]
    if native_id.startswith("SSMParameter:"):
        return _scope_from_typed("SSMParameter", native_id.split(":", 1)[1])[1]
    if native_id.startswith("LambdaFunction:"):
        rest = native_id.split(":", 1)[1]
        return ResourceScope("lambda", "LambdaFunction", native_id, rest)
    if native_id.startswith("Lambda:"):
        # Policy stubs often use Lambda:… — normalize to LambdaFunction for UFC pivots.
        rest = native_id.split(":", 1)[1]
        return ResourceScope("lambda", "LambdaFunction", f"LambdaFunction:{rest}", rest)
    if native_id.startswith("arn:aws:lambda:"):
        return ResourceScope(
            "lambda",
            "LambdaFunction",
            f"LambdaFunction:{native_id}",
            native_id,
        )
    if native_id.startswith("arn:aws:"):
        _nid, scope = resolve_policy_resource(native_id, None)
        return scope
    return None


def parse_ecr_image_uri(uri: str) -> ResourceScope | None:
    """Parse account.dkr.ecr.region.amazonaws.com/repo:tag into an ECR scope."""
    uri = (uri or "").strip()
    match = _ECR_URI_RE.match(uri)
    if not match:
        return None
    account = match.group("account")
    region = match.group("region")
    repo = match.group("repo")
    tag = match.group("tag")
    arn = f"arn:aws:ecr:{region}:{account}:repository/{repo}"
    return ResourceScope(
        family="ecr",
        resource_type="ECRRepository",
        canonical_id=f"ECRRepository:{arn}",
        pattern=arn,
        image_tag=tag,
    )


def intersect_scopes(producer: ResourceScope, consumer: ResourceScope) -> ScopeIntersection | None:
    """Return the narrowest overlapping scope, or None if disjoint."""
    # Different resource types never overlap — except ECR repo ARN ↔ image URI,
    # and Lambda ↔ LambdaFunction (policy stubs vs inventored functions).
    if producer.resource_type != consumer.resource_type:
        lambda_aliases = {"Lambda", "LambdaFunction"}
        if producer.family == consumer.family == "ecr":
            pass
        elif (
            producer.family == consumer.family == "lambda"
            or (
                producer.resource_type in lambda_aliases
                and consumer.resource_type in lambda_aliases
            )
        ):
            pass
        else:
            return None

    if producer.canonical_id.endswith(":*") or producer.pattern == "*":
        return ScopeIntersection(
            scope=consumer if not consumer.is_wildcard else producer,
            match_kind="type_wildcard",
            confidence="wildcard",
        )
    if consumer.canonical_id.endswith(":*") or consumer.pattern == "*":
        return ScopeIntersection(
            scope=producer,
            match_kind="type_wildcard",
            confidence="wildcard",
        )

    if producer.family == "s3":
        return _intersect_s3(producer, consumer)
    if producer.family == "secretsmanager":
        return _intersect_secrets(producer, consumer)
    if producer.family == "ecr":
        return _intersect_ecr(producer, consumer)
    if producer.family == "ssm":
        return _intersect_ssm(producer, consumer)

    if _ids_equal(producer.canonical_id, consumer.canonical_id):
        return ScopeIntersection(producer, "exact", "explicit")
    if _arn_glob_match(producer.pattern, consumer.pattern) or _arn_glob_match(
        consumer.pattern, producer.pattern
    ):
        return ScopeIntersection(_narrower(producer, consumer), "arn_match", "explicit")
    return None


def scopes_from_edge_props(
    *,
    rel_type: str,
    props: dict[str, Any],
    dst_native_id: str | None,
    dst_props: dict[str, Any] | None = None,
) -> ResourceScope | None:
    """Derive a ResourceScope from a graph edge + destination node."""
    dst_props = dst_props or {}
    resource = props.get("resource") or props.get("scope_intersection")
    rtype = (
        props.get("resource_type")
        or dst_props.get("resource_type")
        or _type_from_native(dst_native_id or "")
    )

    if rel_type == "USES_IMAGE":
        image = props.get("image") or dst_props.get("image")
        native = dst_props.get("native_id") or dst_native_id or ""
        if not image and isinstance(native, str):
            if native.startswith("aws:ecs:image:"):
                image = native.split(":", 2)[-1]
            elif native.startswith("kubernetes:image:"):
                image = native.split(":", 2)[-1]
        if image:
            parsed = parse_ecr_image_uri(str(image))
            if parsed:
                return parsed
        return None

    if rel_type == "PULLS_FROM" and dst_native_id:
        return scope_from_native_id(dst_native_id)

    if resource:
        _nid, scope = resolve_policy_resource(str(resource), rtype if isinstance(rtype, str) else None)
        return scope

    if dst_native_id:
        return scope_from_native_id(dst_native_id)
    return None


def _family_for_type(rtype: str) -> str:
    return {
        "S3Bucket": "s3",
        "Secret": "secretsmanager",
        "ECRRepository": "ecr",
        "SSMParameter": "ssm",
        "LambdaFunction": "lambda",
        "Lambda": "lambda",
    }.get(rtype or "", "other")


def _type_from_native(native_id: str) -> str | None:
    if ":" not in native_id:
        return None
    prefix = native_id.split(":", 1)[0]
    if prefix in {"S3Bucket", "Secret", "ECRRepository", "SSMParameter", "LambdaFunction", "Lambda"}:
        return "LambdaFunction" if prefix == "Lambda" else prefix
    return None


def _scope_from_typed(typed: str, rest: str) -> tuple[str, ResourceScope]:
    if rest.startswith("arn:aws:"):
        return resolve_policy_resource(rest, typed)
    nid = f"{typed}:{rest}"
    if typed == "S3Bucket":
        name, _, key = rest.partition("/")
        canon = f"S3Bucket:{name}"
        return canon, ResourceScope("s3", "S3Bucket", canon, nid, path_prefix=key or None)
    if typed == "Secret":
        return nid, ResourceScope("secretsmanager", "Secret", nid, rest)
    if typed == "ECRRepository":
        return nid, ResourceScope("ecr", "ECRRepository", nid, rest)
    if typed == "SSMParameter":
        return nid, ResourceScope("ssm", "SSMParameter", nid, rest, path_prefix=rest)
    return nid, ResourceScope("other", typed, nid, rest)


def _scope_from_s3(resource: str) -> tuple[str, ResourceScope]:
    match = _S3_ARN_RE.match(resource)
    if not match:
        alt = re.search(r":::([^/]+)(?:/(.*))?$", resource)
        if not alt:
            nid = f"S3Bucket:{resource}"
            return nid, ResourceScope("s3", "S3Bucket", nid, resource)
        bucket, key = alt.group(1), alt.group(2)
    else:
        bucket, key = match.group("bucket"), match.group("key")
    nid = f"S3Bucket:{bucket}"
    prefix = key.rstrip("*") if key is not None else None
    return nid, ResourceScope("s3", "S3Bucket", nid, resource, path_prefix=prefix or None)


def _scope_from_secretsmanager(resource: str) -> tuple[str, ResourceScope]:
    nid = f"Secret:{resource}"
    return nid, ResourceScope("secretsmanager", "Secret", nid, resource)


def _scope_from_ecr_arn(resource: str) -> tuple[str, ResourceScope]:
    match = _ECR_ARN_RE.match(resource.rstrip("/*"))
    if match:
        repo = match.group("repo").rstrip("/*")
        arn = (
            f"arn:aws:ecr:{match.group('region')}:{match.group('account')}:"
            f"repository/{repo}"
        )
        nid = f"ECRRepository:{arn}"
        return nid, ResourceScope("ecr", "ECRRepository", nid, arn)
    nid = f"ECRRepository:{resource}"
    return nid, ResourceScope("ecr", "ECRRepository", nid, resource)


def _scope_from_ssm(resource: str) -> tuple[str, ResourceScope]:
    match = _SSM_ARN_RE.match(resource)
    if match:
        path = match.group("path")
        nid = f"SSMParameter:{path}"
        return nid, ResourceScope("ssm", "SSMParameter", nid, resource, path_prefix=f"/{path}")
    path = resource.split("parameter/", 1)[-1] if "parameter/" in resource else resource
    nid = f"SSMParameter:{path.lstrip('/')}"
    return nid, ResourceScope("ssm", "SSMParameter", nid, resource, path_prefix=f"/{path.lstrip('/')}")


def _intersect_s3(a: ResourceScope, b: ResourceScope) -> ScopeIntersection | None:
    a_bucket = a.canonical_id.split(":", 1)[-1]
    b_bucket = b.canonical_id.split(":", 1)[-1]
    if a_bucket != "*" and b_bucket != "*" and a_bucket != b_bucket:
        if not (_arn_glob_match(a_bucket, b_bucket) or _arn_glob_match(b_bucket, a_bucket)):
            return None
    bucket = a_bucket if a_bucket != "*" else b_bucket
    if bucket == "*":
        return ScopeIntersection(b if not b.is_wildcard else a, "type_wildcard", "wildcard")

    a_pref = a.path_prefix or ""
    b_pref = b.path_prefix or ""
    if not a_pref and not b_pref:
        scope = ResourceScope("s3", "S3Bucket", f"S3Bucket:{bucket}", f"arn:aws:s3:::{bucket}")
        return ScopeIntersection(scope, "exact", "explicit")
    if not a_pref:
        inter = b_pref
    elif not b_pref:
        inter = a_pref
    elif a_pref.startswith(b_pref):
        inter = a_pref
    elif b_pref.startswith(a_pref):
        inter = b_pref
    else:
        return None
    scope = ResourceScope(
        "s3",
        "S3Bucket",
        f"S3Bucket:{bucket}",
        f"arn:aws:s3:::{bucket}/{inter}*",
        path_prefix=inter,
    )
    return ScopeIntersection(scope, "prefix" if inter else "exact", "explicit")


def _secret_base_name(pattern: str) -> str:
    name = pattern
    if ":secret:" in name:
        name = name.split(":secret:", 1)[1]
    if name.startswith("Secret:"):
        name = name.split(":", 1)[1]
        if ":secret:" in name:
            name = name.split(":secret:", 1)[1]
    name = name.rstrip("*")
    return re.sub(r"-[A-Za-z0-9]{6}$", "", name)


def _intersect_secrets(a: ResourceScope, b: ResourceScope) -> ScopeIntersection | None:
    if _ids_equal(a.canonical_id, b.canonical_id) or a.pattern == b.pattern:
        return ScopeIntersection(_narrower(a, b), "exact", "explicit")
    a_name = _secret_base_name(a.pattern)
    b_name = _secret_base_name(b.pattern)
    if a_name and b_name and (
        a_name == b_name or a_name.startswith(b_name) or b_name.startswith(a_name)
    ):
        return ScopeIntersection(_narrower(a, b), "arn_match", "explicit")
    if _arn_glob_match(a.pattern, b.pattern) or _arn_glob_match(b.pattern, a.pattern):
        return ScopeIntersection(_narrower(a, b), "arn_match", "explicit")
    return None


def _intersect_ecr(a: ResourceScope, b: ResourceScope) -> ScopeIntersection | None:
    a_repo = _ecr_repo_key(a)
    b_repo = _ecr_repo_key(b)
    if not a_repo or not b_repo:
        if _arn_glob_match(a.pattern, b.pattern) or _arn_glob_match(b.pattern, a.pattern):
            return ScopeIntersection(_narrower(a, b), "arn_match", "wildcard")
        return None
    if a_repo != b_repo:
        if not (_arn_glob_match(a_repo, b_repo) or _arn_glob_match(b_repo, a_repo)):
            return None
    if a.image_tag and b.image_tag and a.image_tag != b.image_tag:
        return None
    tag = a.image_tag or b.image_tag
    canon = a.canonical_id if a.canonical_id.startswith("ECRRepository:arn:") else b.canonical_id
    pattern = a.pattern if a.pattern.startswith("arn:") else b.pattern
    scope = ResourceScope("ecr", "ECRRepository", canon, pattern, image_tag=tag)
    kind = "exact" if (a.image_tag and b.image_tag) or (not a.image_tag and not b.image_tag) else "prefix"
    return ScopeIntersection(scope, kind, "explicit")


def _ecr_repo_key(scope: ResourceScope) -> str | None:
    candidate = scope.pattern
    if scope.canonical_id.startswith("ECRRepository:"):
        candidate = scope.canonical_id.split(":", 1)[1]
    m = _ECR_ARN_RE.match(candidate.rstrip("/*"))
    if m:
        return f"{m.group('account')}/{m.group('region')}/{m.group('repo').rstrip('/*')}"
    parsed = parse_ecr_image_uri(scope.pattern)
    if parsed:
        return _ecr_repo_key(parsed)
    return None


def _intersect_ssm(a: ResourceScope, b: ResourceScope) -> ScopeIntersection | None:
    a_path = (a.path_prefix or a.canonical_id.split(":", 1)[-1]).lstrip("/")
    b_path = (b.path_prefix or b.canonical_id.split(":", 1)[-1]).lstrip("/")
    if a_path == b_path or a_path.startswith(b_path) or b_path.startswith(a_path):
        narrower = a_path if len(a_path) >= len(b_path) else b_path
        scope = ResourceScope(
            "ssm",
            "SSMParameter",
            f"SSMParameter:{narrower}",
            f"/{narrower}",
            path_prefix=f"/{narrower}",
        )
        return ScopeIntersection(scope, "prefix" if a_path != b_path else "exact", "explicit")
    if _arn_glob_match(a.pattern, b.pattern) or _arn_glob_match(b.pattern, a.pattern):
        return ScopeIntersection(_narrower(a, b), "arn_match", "wildcard")
    return None


def _narrower(a: ResourceScope, b: ResourceScope) -> ResourceScope:
    if a.is_wildcard and not b.is_wildcard:
        return b
    if b.is_wildcard and not a.is_wildcard:
        return a
    return a if len(a.pattern) >= len(b.pattern) else b


def _ids_equal(a: str, b: str) -> bool:
    return a == b or a.rstrip("*") == b.rstrip("*")


def _arn_glob_match(pattern: str, value: str) -> bool:
    if not pattern or not value:
        return False
    if pattern == "*":
        return True
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(rx, value) is not None
