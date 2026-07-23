"""Normalize third-party scanner / tool output into enrichment materials.

Samoyed does not reimplement those scanners — operators run them (or drop their
JSON) and we consolidate into the enrichment report schema.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol


class MaterialAdapter(Protocol):
    name: str

    def ingest(self, payload: Any, *, source_label: str) -> list[dict[str, Any]]:
        """Return enrichment material dicts (kind/locator/confidence/evidence)."""


def load_json_payload(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def adapt_tool_report(
    payload: Any,
    *,
    source_label: str,
    tool: str | None = None,
) -> list[dict[str, Any]]:
    """
    Auto-detect a known tool report shape and normalize findings.

    Unknown shapes raise ValueError so callers can fall back or fail loudly.
    """
    inferred = tool or infer_tool_format(payload)
    if inferred == "trufflehog":
        return TrufflehogAdapter().ingest(payload, source_label=source_label)
    if inferred == "gitleaks":
        return GitleaksAdapter().ingest(payload, source_label=source_label)
    if inferred == "samoyed-enrichment":
        return _materials_from_enrichment(payload)
    if inferred == "generic-findings":
        return GenericFindingsAdapter().ingest(payload, source_label=source_label)
    raise ValueError(
        f"Unrecognized tool report format ({source_label}). "
        "Supported: trufflehog, gitleaks, samoyed-enrichment, or "
        '{"findings":[{"kind":..., "locator":...}]}'
    )


def infer_tool_format(payload: Any) -> str:
    if isinstance(payload, dict):
        if payload.get("enrichment_version") and isinstance(payload.get("bindings"), list):
            return "samoyed-enrichment"
        if isinstance(payload.get("findings"), list):
            return "generic-findings"
        # gitleaks JSON often has {"DerivedFrom":..., "Findings":[...]} or bare list exported separately
        if isinstance(payload.get("Findings"), list) or "SourceMetadata" in payload:
            return "gitleaks"
    if isinstance(payload, list):
        if not payload:
            return "generic-findings"
        first = payload[0]
        if isinstance(first, dict):
            if "SourceMetadata" in first or first.get("DetectorName") or first.get("DecoderName"):
                return "trufflehog"
            if "RuleID" in first or "Description" in first and "Secret" in first:
                return "gitleaks"
            if "kind" in first and "locator" in first:
                return "generic-findings"
    raise ValueError("Unable to infer tool report format")


def _materials_from_enrichment(payload: dict[str, Any]) -> list[dict[str, Any]]:
    materials: list[dict[str, Any]] = []
    for binding in payload.get("bindings") or []:
        for material in binding.get("materials") or []:
            if isinstance(material, dict):
                materials.append(dict(material))
    return materials


class GenericFindingsAdapter:
    """Operator-supplied findings already close to our material schema."""

    name = "generic-findings"

    def ingest(self, payload: Any, *, source_label: str) -> list[dict[str, Any]]:
        rows = payload.get("findings") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise ValueError("generic findings payload must be a list or {findings: [...]}")
        out: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict) or not row.get("kind"):
                continue
            item = {
                "kind": str(row["kind"]),
                "locator": str(row.get("locator") or f"{source_label}:{row['kind']}"),
                "confidence": str(row.get("confidence") or "inferred"),
                "evidence": {
                    **(row.get("evidence") or {}),
                    "adapter": self.name,
                    "source_report": source_label,
                },
            }
            if row.get("resolves_to"):
                item["resolves_to"] = row["resolves_to"]
            out.append(item)
        return out


class TrufflehogAdapter:
    """Normalize TruffleHog JSON (array of detector results or NDJSON-loaded list)."""

    name = "trufflehog"

    def ingest(self, payload: Any, *, source_label: str) -> list[dict[str, Any]]:
        rows = payload if isinstance(payload, list) else [payload]
        out: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            kind = _trufflehog_kind(row)
            locator = _trufflehog_locator(row, source_label=source_label)
            out.append(
                {
                    "kind": kind,
                    "locator": locator,
                    "confidence": "explicit" if row.get("Verified") else "inferred",
                    "evidence": {
                        "adapter": self.name,
                        "source_report": source_label,
                        "detector": row.get("DetectorName") or row.get("DetectorType"),
                        "verified": bool(row.get("Verified")),
                    },
                }
            )
        return out


class GitleaksAdapter:
    """Normalize gitleaks JSON export (operator-run against a *target*, not Samoyed's pre-commit)."""

    name = "gitleaks"

    def ingest(self, payload: Any, *, source_label: str) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            rows = payload.get("Findings") or payload.get("findings") or []
        else:
            rows = payload
        if not isinstance(rows, list):
            raise ValueError("gitleaks payload must be a list or {Findings: [...]}")
        out: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            kind = _gitleaks_kind(row)
            file_path = str(row.get("File") or row.get("FilePath") or "unknown")
            rule = str(row.get("RuleID") or row.get("Description") or "secret")
            locator = f"{file_path}:{rule}"
            out.append(
                {
                    "kind": kind,
                    "locator": locator,
                    "confidence": "explicit",
                    "evidence": {
                        "adapter": self.name,
                        "source_report": source_label,
                        "rule_id": row.get("RuleID"),
                        "description": row.get("Description"),
                        "file": file_path,
                        "line": row.get("StartLine") or row.get("Line"),
                    },
                }
            )
        return out


def _trufflehog_kind(row: dict[str, Any]) -> str:
    detector = str(row.get("DetectorName") or row.get("DetectorType") or "").lower()
    if "aws" in detector:
        if "secret" in detector:
            return "aws_secret_key_env"
        return "aws_access_key_env"
    if "gcp" in detector or "google" in detector:
        return "gcp_service_account_json"
    if "azure" in detector:
        return "azure_client_secret_env"
    if "kubernetes" in detector or "kube" in detector:
        return "kubeconfig_file"
    if "postgres" in detector or "mysql" in detector or "mongo" in detector or "jdbc" in detector:
        return "database_connection_string"
    return "generic_credential_file"


def _trufflehog_locator(row: dict[str, Any], *, source_label: str) -> str:
    meta = row.get("SourceMetadata") or {}
    data = meta.get("Data") if isinstance(meta, dict) else None
    if isinstance(data, dict):
        for key in ("Filesystem", "Git"):
            block = data.get(key)
            if isinstance(block, dict) and block.get("file"):
                line = block.get("line")
                path = block["file"]
                return f"{path}:{line}" if line else str(path)
    return f"{source_label}:{row.get('DetectorName') or 'finding'}"


def _gitleaks_kind(row: dict[str, Any]) -> str:
    blob = " ".join(
        str(row.get(k) or "")
        for k in ("RuleID", "Description", "Tags", "Secret", "Match")
    ).lower()
    if "aws" in blob and "secret" in blob:
        return "aws_secret_key_env"
    if "aws" in blob or "akia" in blob:
        return "aws_access_key_env"
    if "gcp" in blob or "google" in blob:
        return "gcp_service_account_json"
    if "azure" in blob:
        return "azure_client_secret_env"
    if "kube" in blob:
        return "kubeconfig_file"
    if "postgres" in blob or "mysql" in blob or "connection" in blob:
        return "database_connection_string"
    return "generic_credential_file"
