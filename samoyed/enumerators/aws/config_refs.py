"""Parse declared resource refs from compute/control-plane configs.

Config-declared deps (env ARNs, secrets blocks, image URIs) are high-confidence
READS / PULLS_FROM / USES_IMAGE edges — distinct from IAM capability grants.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptEdge
from samoyed.cloud.concepts import ConceptType, ConfidenceType
from samoyed.graph.resource_scope import parse_ecr_image_uri

# ARNs / URIs commonly pasted into Lambda env, Batch env, Glue scripts, etc.
_SECRET_ARN = re.compile(
    r"arn:aws:secretsmanager:[a-z0-9-]+:\d+:secret:[A-Za-z0-9/_+=.@-]+"
)
_SSM_ARN = re.compile(r"arn:aws:ssm:[a-z0-9-]+:\d+:parameter(/[A-Za-z0-9/_.-]+)")
_SSM_PATH = re.compile(r"(?:^|[\s\"'=])(/[A-Za-z0-9/_.-]{2,})")
_S3_ARN = re.compile(r"arn:aws:s3:::[A-Za-z0-9._-]+(?:/[^\s\"']*)?")
_S3_URI = re.compile(r"s3://([A-Za-z0-9._-]+)(?:/[^\s\"']*)?")
_KMS_ARN = re.compile(r"arn:aws:kms:[a-z0-9-]+:\d+:key/[A-Fa-f0-9-]+")
_KMS_ALIAS = re.compile(r"arn:aws:kms:[a-z0-9-]+:\d+:alias/[A-Za-z0-9/_-]+")


def iter_string_values(obj: Any) -> Iterator[str]:
    """Walk nested dict/list config and yield string leaves."""
    if isinstance(obj, str):
        yield obj
        return
    if isinstance(obj, dict):
        for v in obj.values():
            yield from iter_string_values(v)
        return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            yield from iter_string_values(item)


def extract_resource_refs(text: str) -> list[tuple[str, str, ConceptType]]:
    """Return (native_id, resource_type, concept) refs discovered in free text."""
    found: list[tuple[str, str, ConceptType]] = []
    seen: set[str] = set()

    def add(native_id: str, rtype: str, concept: ConceptType) -> None:
        if native_id not in seen:
            seen.add(native_id)
            found.append((native_id, rtype, concept))

    for m in _SECRET_ARN.finditer(text):
        arn = _strip_secret_json_key(m.group(0))
        add(f"Secret:{arn}", "Secret", ConceptType.SECRET_STORE)

    for m in _SSM_ARN.finditer(text):
        path = m.group(1)
        add(f"SSMParameter:{path.lstrip('/')}", "SSMParameter", ConceptType.SECRET_STORE)

    for m in _S3_ARN.finditer(text):
        arn = m.group(0)
        bucket = arn.replace("arn:aws:s3:::", "").split("/", 1)[0]
        add(f"S3Bucket:{bucket}", "S3Bucket", ConceptType.DATA_STORE)

    for m in _S3_URI.finditer(text):
        add(f"S3Bucket:{m.group(1)}", "S3Bucket", ConceptType.DATA_STORE)

    for m in _KMS_ARN.finditer(text):
        add(f"KMSKey:{m.group(0)}", "KMSKey", ConceptType.DATA_STORE)
    for m in _KMS_ALIAS.finditer(text):
        add(f"KMSKey:{m.group(0)}", "KMSKey", ConceptType.DATA_STORE)

    return found


def _strip_secret_json_key(arn: str) -> str:
    """Secrets Manager valueFrom may append :JSONKEY after the random suffix."""
    parts = arn.split(":secret:", 1)
    if len(parts) != 2:
        return arn
    name_part = parts[1]
    # name-AbCdEf:MYKEY → keep name-AbCdEf
    if ":" in name_part:
        # Random suffix is 6 chars after final '-'; keep at most one extra ':' segment
        # when it looks like a JSON key (no hyphens typical of suffix).
        base, maybe_key = name_part.rsplit(":", 1)
        if maybe_key and not maybe_key.startswith("-"):
            name_part = base
    return f"{parts[0]}:secret:{name_part}"


def config_reads_edges(
    *,
    source: str,
    env: dict[str, str] | None = None,
    extra_blobs: list[Any] | None = None,
    image_uri: str | None = None,
) -> list[ConceptEdge]:
    """Build declared-config edges for a compute resource."""
    edges: list[ConceptEdge] = []
    blobs: list[Any] = []
    if env:
        blobs.append(env)
    if extra_blobs:
        blobs.extend(extra_blobs)

    for blob in blobs:
        for text in iter_string_values(blob):
            for native_id, rtype, concept in extract_resource_refs(text):
                edges.append(
                    ConceptEdge(
                        rel_type="READS" if rtype != "KMSKey" else "CONTROLS",
                        target_native_id=native_id,
                        target_concept_type=concept,
                        props={
                            "resource": native_id.split(":", 1)[-1],
                            "resource_type": rtype,
                            "source": source,
                            "discovered_via": "config",
                        },
                        confidence=ConfidenceType.EXPLICIT,
                    )
                )

    if image_uri:
        image_id = f"aws:lambda:image:{image_uri}"
        edges.append(
            ConceptEdge(
                rel_type="USES_IMAGE",
                target_native_id=image_id,
                target_concept_type=ConceptType.IMAGE_PROVENANCE,
                props={"image": image_uri, "source": source, "discovered_via": "config"},
            )
        )
        ecr = parse_ecr_image_uri(image_uri)
        if ecr:
            edges.append(
                ConceptEdge(
                    rel_type="PULLS_FROM",
                    src_native_id=image_id,
                    target_native_id=ecr.canonical_id,
                    target_concept_type=ConceptType.REGISTRY_STORE,
                    props={
                        "image": image_uri,
                        "resource": ecr.pattern,
                        "resource_type": "ECRRepository",
                        "source": source,
                        "discovered_via": "config",
                    },
                )
            )
    return _dedupe_edges(edges)


def _dedupe_edges(edges: list[ConceptEdge]) -> list[ConceptEdge]:
    seen: set[tuple[str, str, str]] = set()
    out: list[ConceptEdge] = []
    for e in edges:
        key = (e.rel_type, e.src_native_id or "", e.target_native_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out
