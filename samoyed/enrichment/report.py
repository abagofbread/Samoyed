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
    host_native_id: str | None = None,
) -> str:
    """Stable material id — host-independent so re-imports upsert the same node.

    ``host_native_id`` is accepted for backward compatibility but ignored.
    """
    _ = host_native_id
    key = f"{kind}|{locator.strip()}|{fingerprint or ''}"
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
