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
    "aws_autoscaling_group": "ec2_asg",
    "aws_launch_template": "launch_template",
}


def secret_fingerprint(value: str) -> str:
    normalized = value.strip().strip("\"'")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


# Prefer more impactful kinds when collapsing same-value findings.
_KIND_RANK: dict[str, int] = {
    "database_connection_string": 40,
    "aws_secret_key_env": 35,
    "aws_session_token_env": 34,
    "aws_access_key_env": 33,
    "azure_client_secret_env": 32,
    "generic_credential_file": 20,
    "kubeconfig_file": 15,
    "k8s_service_account_token": 15,
}

_DB_COLLAPSE_KINDS = frozenset({"generic_credential_file", "database_connection_string"})


def collapse_materials_by_fingerprint(materials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One material per secret value; observation sites live on ``seen_at``.

    Findings without a fingerprint pass through unchanged (location-keyed).
    """
    out: list[dict[str, Any]] = []
    by_fp: dict[str, int] = {}
    for material in materials:
        fp = material.get("secret_fingerprint")
        if not fp or not isinstance(fp, str):
            out.append(material)
            continue
        if fp in by_fp:
            _merge_fingerprint_material(out[by_fp[fp]], material)
            continue
        merged = dict(material)
        locator = str(merged.get("locator") or "")
        seen = [locator] if locator else []
        for loc in merged.get("also_seen_in") or []:
            text = str(loc)
            if text and text not in seen:
                seen.append(text)
        merged["seen_at"] = seen
        if len(seen) > 1:
            merged["reuse_count"] = len(seen)
            merged["also_seen_in"] = [s for s in seen if s != locator]
            evidence = dict(merged.get("evidence") or {})
            evidence["credential_reuse"] = True
            evidence["reuse_count"] = len(seen)
            evidence["also_seen_in"] = merged["also_seen_in"]
            evidence["seen_at"] = seen
            merged["evidence"] = evidence
        by_fp[fp] = len(out)
        out.append(merged)
    return collapse_materials_by_impact(out)


def collapse_materials_by_impact(materials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse DB-related findings that unlock the same datastore.

    Password materials, RDS_ENDPOINT refs, and Secrets Manager resource
    references that all map to ``aws-goat-db`` become one PivotMaterial;
    observation sites stay on ``seen_at`` (and later on HAS_MATERIAL edges).
    """
    out: list[dict[str, Any]] = []
    by_impact: dict[str, int] = {}
    for material in materials:
        key = db_impact_key(material)
        if not key:
            out.append(material)
            continue
        if key in by_impact:
            _merge_fingerprint_material(out[by_impact[key]], material)
            existing = out[by_impact[key]]
            existing["impact_key"] = key
            _prefer_credential_finding(existing, material)
            continue
        merged = dict(material)
        merged["impact_key"] = key
        locator = str(merged.get("locator") or "")
        seen = list(merged.get("seen_at") or [])
        if locator and locator not in seen:
            seen.insert(0, locator)
        for loc in merged.get("also_seen_in") or []:
            text = str(loc)
            if text and text not in seen:
                seen.append(text)
        merged["seen_at"] = seen
        if len(seen) > 1:
            merged["reuse_count"] = max(len(seen), int(merged.get("reuse_count") or 0))
            merged["also_seen_in"] = [s for s in seen if s != merged.get("locator")]
        by_impact[key] = len(out)
        out.append(merged)
    return out


def db_impact_key(material: dict[str, Any]) -> str | None:
    """Stable collapse key for DB credential / reference findings."""
    kind = str(material.get("kind") or "")
    if kind not in _DB_COLLAPSE_KINDS:
        return None
    for row in material.get("impact_targets") or []:
        if not isinstance(row, dict):
            continue
        if row.get("kind") == "db_instance" and row.get("name"):
            return f"db_instance:{row['name']}"
    # Fallback: single db-ish name hint (avoid secret names like RDS_CREDS).
    for hint in material.get("name_hints") or []:
        text = str(hint).strip()
        if not text:
            continue
        low = text.lower()
        if any(tok in low for tok in ("cred", "secret", "token", "password", "vault")):
            continue
        if any(tok in low for tok in ("db", "rds", "mysql", "postgres", "aurora", "database")) or low.endswith("-db"):
            return f"db_instance:{text}"
    return None


def _finding_rank(material: dict[str, Any]) -> int:
    finding = str(material.get("finding") or "").lower()
    match = ""
    evidence = material.get("evidence")
    if isinstance(evidence, dict):
        match = str(evidence.get("match") or "").lower()
    blob = f"{finding} {match}"
    if "password" in blob or "mysql" in blob:
        return 100
    if material.get("secret_fingerprint"):
        return 90
    if "connection string" in blob or "dsn" in blob:
        return 70
    if "secret reference" in blob or "secretsmanager" in blob:
        return 40
    if "endpoint" in blob:
        return 30
    return 10


def _prefer_credential_finding(existing: dict[str, Any], other: dict[str, Any]) -> None:
    """Keep the most concrete credential finding as the node label source."""
    if _finding_rank(other) <= _finding_rank(existing):
        return
    for key in ("finding", "summary", "kind", "locator", "confidence"):
        if other.get(key):
            existing[key] = other[key]
    if other.get("secret_fingerprint"):
        existing["secret_fingerprint"] = other["secret_fingerprint"]
    other_ev = other.get("evidence") if isinstance(other.get("evidence"), dict) else {}
    if other_ev:
        evidence = dict(existing.get("evidence") or {})
        for key in ("match", "file", "line", "finding"):
            if other_ev.get(key) is not None:
                evidence[key] = other_ev[key]
        existing["evidence"] = evidence


def _merge_fingerprint_material(existing: dict[str, Any], other: dict[str, Any]) -> None:
    """Fold another observation of the same secret into ``existing``."""
    locator = str(other.get("locator") or "")
    seen: list[str] = list(existing.get("seen_at") or [])
    primary = str(existing.get("locator") or "")
    if primary and primary not in seen:
        seen.insert(0, primary)
    for loc in [locator, *(other.get("seen_at") or []), *(other.get("also_seen_in") or [])]:
        text = str(loc)
        if text and text not in seen:
            seen.append(text)
    existing["seen_at"] = seen
    existing["reuse_count"] = max(len(seen), int(existing.get("reuse_count") or 0), int(other.get("reuse_count") or 0))
    existing["also_seen_in"] = [s for s in seen if s != existing.get("locator")]

    other_kind = str(other.get("kind") or "")
    exist_kind = str(existing.get("kind") or "")
    if _KIND_RANK.get(other_kind, 0) > _KIND_RANK.get(exist_kind, 0):
        existing["kind"] = other_kind
        # Prefer the more specific finding's labels/locator as primary.
        if locator:
            existing["locator"] = locator
        for key in ("finding", "summary", "confidence"):
            if other.get(key):
                existing[key] = other[key]

    kinds = list(existing.get("material_kinds") or [])
    for kind in (exist_kind, other_kind):
        if kind and kind not in kinds:
            kinds.append(kind)
    if kinds:
        existing["material_kinds"] = kinds

    hints = list(existing.get("name_hints") or [])
    for hint in other.get("name_hints") or []:
        if hint and hint not in hints:
            hints.append(hint)
    if hints:
        existing["name_hints"] = hints

    impacts = list(existing.get("impact_targets") or [])
    seen_impact = {(r.get("kind"), r.get("name")) for r in impacts if isinstance(r, dict)}
    for row in other.get("impact_targets") or []:
        if not isinstance(row, dict):
            continue
        key = (row.get("kind"), row.get("name"))
        if key in seen_impact:
            continue
        seen_impact.add(key)
        impacts.append(row)
    if impacts:
        existing["impact_targets"] = impacts

    if other.get("secret_fingerprint") and not existing.get("secret_fingerprint"):
        existing["secret_fingerprint"] = other["secret_fingerprint"]
    if other.get("impact_key") and not existing.get("impact_key"):
        existing["impact_key"] = other["impact_key"]
    _prefer_credential_finding(existing, other)

    evidence = dict(existing.get("evidence") or {})
    evidence["credential_reuse"] = True
    evidence["reuse_count"] = existing["reuse_count"]
    evidence["also_seen_in"] = existing.get("also_seen_in") or []
    evidence["seen_at"] = seen
    existing["evidence"] = evidence
    existing["confidence"] = existing.get("confidence") or other.get("confidence") or "explicit"


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
    from samoyed.collectors.sa_token import (
        decode_jwt_payload,
        enrich_sa_token_material,
        sa_ref_from_jwt_payload,
    )

    by_fp: dict[str, list[int]] = {}
    for idx, material in enumerate(materials):
        raw = material.pop("_secret_value", None)
        # SA JWT: derive impact_targets from claims before discarding the secret.
        if (
            raw
            and isinstance(raw, str)
            and str(material.get("kind") or "") == "k8s_service_account_token"
        ):
            payload = decode_jwt_payload(raw)
            if payload:
                evidence = dict(material.get("evidence") or {})
                evidence["jwt_iss"] = payload.get("iss")
                evidence["jwt_sub"] = payload.get("sub")
                material["evidence"] = evidence
                ref = sa_ref_from_jwt_payload(payload)
                if ref:
                    ns, sa = ref
                    target = {"kind": "k8s_service_account", "name": f"{ns}:{sa}"}
                    targets = list(material.get("impact_targets") or [])
                    if target not in targets:
                        targets.append(target)
                    material["impact_targets"] = targets
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
                # Emit typed impact_targets (registry keys in enrichment.impact).
                # Concrete DB instance name — not Secrets Manager vault labels.
                dbs = [
                    r
                    for r in (same_file or declared_resources)
                    if r.get("kind") == "db_instance" and r.get("name")
                ] or [{"name": n, "kind": "db_instance"} for n in db_names]
                material["impact_targets"] = [
                    {"name": r["name"], "kind": "db_instance"} for r in dbs if r.get("name")
                ]
                hints.extend(r["name"] for r in dbs if r.get("name"))
                # Keep vault names in hints so Secret:* can UNLOCKS the DB with where=.
                hints.extend(
                    r["name"]
                    for r in (same_file or declared_resources)
                    if r.get("kind") == "secretsmanager_secret" and r.get("name")
                )
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
    materials = [enrich_sa_token_material(m) for m in materials]
    return collapse_materials_by_fingerprint(materials)
