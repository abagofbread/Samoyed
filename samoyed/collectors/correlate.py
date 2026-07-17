"""Correlate collector findings: shared secrets + Terraform name hints."""

from __future__ import annotations

import hashlib
import re
from typing import Any

_RESOURCE_START = re.compile(r'resource\s+"(aws_[^"]+)"\s+"([^"]+)"\s*\{')
_NAME_FIELD = re.compile(
    r'\b(?:name|identifier|bucket|cluster|function_name|role|family)\s*=\s*"([^"${\n]+)"'
)

_TYPE_HINTS = {
    "aws_iam_role": "iam_role",
    "aws_iam_user": "iam_user",
    "aws_secretsmanager_secret": "secretsmanager_secret",
    "aws_db_instance": "db_instance",
    "aws_s3_bucket": "s3_bucket",
    "aws_ecs_cluster": "ecs_cluster",
    "aws_ecs_service": "ecs_service",
    "aws_ecs_task_definition": "ecs_task_definition",
    "aws_lambda_function": "lambda_function",
    "aws_instance": "ec2_instance",
}


def secret_fingerprint(value: str) -> str:
    normalized = value.strip().strip("\"'")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def extract_terraform_names(text: str, *, source_path: str) -> list[dict[str, str]]:
    """Pull human names/identifiers from Terraform resource block headers."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in _RESOURCE_START.finditer(text):
        aws_type = match.group(1)
        addr = match.group(2)
        kind = _TYPE_HINTS.get(aws_type)
        if not kind:
            continue
        header = text[match.end() : match.end() + 1500]
        next_res = header.find('\nresource "')
        if next_res != -1:
            header = header[:next_res]
        name_match = _NAME_FIELD.search(header)
        name = (name_match.group(1).strip() if name_match else addr).strip()
        if not name:
            continue
        key = (kind, name)
        if key in seen:
            continue
        seen.add(key)
        found.append(
            {
                "kind": kind,
                "name": name,
                "tf_address": f"{aws_type}.{addr}",
                "source": source_path,
            }
        )
    return found


def correlate_materials(
    materials: list[dict[str, Any]],
    *,
    declared_resources: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """
    Link findings that share a secret fingerprint and attach rough TF name hints.

    Consumes transient ``_secret_value`` (stripped before return). Never persists raw secrets.
    """
    by_fp: dict[str, list[int]] = {}
    for idx, material in enumerate(materials):
        raw = material.pop("_secret_value", None)
        if not raw or not isinstance(raw, str):
            continue
        if len(raw.strip().strip("\"'")) < 4:
            continue
        fp = secret_fingerprint(raw)
        material["secret_fingerprint"] = fp
        evidence = dict(material.get("evidence") or {})
        evidence["secret_fingerprint"] = fp
        material["evidence"] = evidence
        by_fp.setdefault(fp, []).append(idx)

    for _fp, indexes in by_fp.items():
        if len(indexes) < 2:
            continue
        locators = [str(materials[i].get("locator") or "") for i in indexes]
        for i in indexes:
            material = materials[i]
            others = [loc for loc in locators if loc != material.get("locator")]
            material["reuse_count"] = len(indexes)
            material["also_seen_in"] = others
            material["confidence"] = "explicit"
            evidence = dict(material.get("evidence") or {})
            evidence["credential_reuse"] = True
            evidence["reuse_count"] = len(indexes)
            evidence["also_seen_in"] = others
            material["evidence"] = evidence

    if declared_resources:
        secret_names = [
            r["name"] for r in declared_resources if r.get("kind") == "secretsmanager_secret"
        ]
        db_names = [r["name"] for r in declared_resources if r.get("kind") == "db_instance"]
        role_names = [r["name"] for r in declared_resources if r.get("kind") == "iam_role"]
        for material in materials:
            hints: list[str] = list(material.get("name_hints") or [])
            kind = str(material.get("kind") or "")
            locator = str(material.get("locator") or "")
            evidence = material.get("evidence") if isinstance(material.get("evidence"), dict) else {}
            mat_file = str(evidence.get("file") or "")
            basename = mat_file.replace("\\", "/").rsplit("/", 1)[-1] if mat_file else ""
            same_file = [
                r
                for r in declared_resources
                if r.get("name")
                and basename
                and str(r.get("source") or "").replace("\\", "/").endswith(basename)
            ]
            same_roles = [r["name"] for r in same_file if r.get("kind") == "iam_role"]

            if kind in {"generic_credential_file", "database_connection_string"}:
                # Impact is the database instance — not Secrets Manager secret names.
                dbs = [
                    r
                    for r in (same_file or declared_resources)
                    if r.get("kind") == "db_instance" and r.get("name")
                ] or [{"name": n, "kind": "db_instance"} for n in db_names]
                material["impact_targets"] = [
                    {"name": r["name"], "kind": "db_instance"} for r in dbs if r.get("name")
                ]
                hints.extend(r["name"] for r in dbs if r.get("name"))
            match_l = str(evidence.get("match") or "").lower()
            if kind.startswith("aws_") and (
                "secret" in locator.lower() or "secretsmanager" in match_l
            ):
                hints.extend(secret_names[:2])
            if kind.startswith("aws_") or "iam" in locator.lower() or "role" in locator.lower():
                hints.extend(same_roles or role_names[:3])
            material["name_hints"] = list(dict.fromkeys(h for h in hints if h))

    for material in materials:
        material.pop("_secret_value", None)
    return materials
