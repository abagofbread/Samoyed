from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

ENRICHMENT_VERSION = 1


def parse_enrichment_report(payload: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, dict):
        data = payload
    else:
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Enrichment report must be a JSON object")
    version = int(data.get("enrichment_version") or 0)
    if version != ENRICHMENT_VERSION:
        raise ValueError(f"Unsupported enrichment_version {version} (expected {ENRICHMENT_VERSION})")
    if not isinstance(data.get("bindings"), list):
        raise ValueError("Enrichment report requires a bindings array")
    return data


def material_native_id(
    kind: str,
    locator: str,
    *,
    fingerprint: str | None = None,
    impact_key: str | None = None,
    host_native_id: str | None = None,
) -> str:
    """Stable material id — host-independent so re-imports upsert the same node.

    Priority:
    1. ``fingerprint`` — same secret value collapses regardless of path/kind
    2. ``impact_key`` — same DB impact (e.g. ``db_instance:aws-goat-db``) collapses
       password + endpoint + Secrets Manager references into one node
    3. kind+locator — findings with neither fingerprint nor shared impact

    ``host_native_id`` is accepted for backward compatibility but ignored.
    """
    _ = host_native_id
    fp = (fingerprint or "").strip()
    if fp:
        # secret_fingerprint is typically ``sha256:<16 hex>``; keep a short stable digest.
        token = fp.split(":", 1)[-1] if fp.startswith("sha256:") else fp
        if len(token) >= 8 and all(c in "0123456789abcdef" for c in token.lower()):
            return f"material:fp:{token[:16].lower()}"
        digest = hashlib.sha256(fp.encode("utf-8")).hexdigest()[:16]
        return f"material:fp:{digest}"
    impact = (impact_key or "").strip()
    if impact:
        # Keep readable when short; hash otherwise.
        safe = "".join(c if c.isalnum() or c in "._:-" else "-" for c in impact)
        if 0 < len(safe) <= 96:
            return f"material:impact:{safe}"
        digest = hashlib.sha256(impact.encode("utf-8")).hexdigest()[:16]
        return f"material:impact:{digest}"
    key = f"{kind}|{locator.strip()}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"material:{kind}:{digest}"


def default_report(
    *,
    collector: str,
    collector_mode: str = "remote-query",
    bindings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "enrichment_version": ENRICHMENT_VERSION,
        "collector": collector,
        "collector_mode": collector_mode,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "bindings": bindings or [],
    }
