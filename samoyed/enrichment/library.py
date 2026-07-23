"""Local enrichment library under ``~/.samoyed/enrichments`` (or ``SAMOYED_ENRICHMENT_DIR``)."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from samoyed.graph.persistence import default_samoyed_home

_SAFE_STEM = re.compile(r"[^a-zA-Z0-9._-]+")


def default_enrichment_dir() -> Path:
    """Where collector reports land by default.

    Override with ``SAMOYED_ENRICHMENT_DIR``, else ``$SAMOYED_HOME/enrichments``.
    """
    env = os.environ.get("SAMOYED_ENRICHMENT_DIR")
    if env:
        return Path(env).expanduser()
    return default_samoyed_home() / "enrichments"


def ensure_enrichment_dir(directory: Path | None = None) -> Path:
    path = directory or default_enrichment_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def sanitize_enrichment_stem(name: str) -> str:
    stem = Path(str(name).strip()).stem or "enrichment"
    stem = _SAFE_STEM.sub("-", stem).strip(".-_")
    return stem[:80] or "enrichment"


def stem_from_collect_target(target: str) -> str:
    """Derive a stable default filename stem from a collect target."""
    raw = str(target).strip()
    lowered = raw.lower()
    if lowered in {"host", "host:local", "local", "localhost", "on-host"}:
        return "host-local"
    path = Path(raw).expanduser()
    if path.exists():
        if path.is_file():
            return sanitize_enrichment_stem(path.stem)
        # Prefer leaf dir name (module-2) over a generic parent
        name = path.name or path.stem
        return sanitize_enrichment_stem(name)
    # Non-existent path token — still use basename
    return sanitize_enrichment_stem(Path(raw).name or raw)


def resolve_collect_output_path(
    target: str,
    *,
    output: Path | None = None,
    name: str | None = None,
    directory: Path | None = None,
) -> Path:
    """
    Decide where to write a collect report.

    - Explicit ``output`` path wins (any location).
    - Else ``directory`` / ``{name|target-stem}.json`` under the enrichment library.
    """
    if output is not None:
        return output.expanduser()
    stem = sanitize_enrichment_stem(name) if name else stem_from_collect_target(target)
    return ensure_enrichment_dir(directory) / f"{stem}.json"


def list_enrichment_library(directory: Path | None = None) -> list[dict[str, Any]]:
    """List enrichment JSON files in the library directory (newest first)."""
    root = directory or default_enrichment_dir()
    if not root.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in root.glob("*.json"):
        if not path.is_file():
            continue
        meta = _library_file_meta(path)
        if meta:
            items.append(meta)
    items.sort(key=lambda row: row.get("modified_at") or "", reverse=True)
    return items


def read_enrichment_library_file(
    filename: str,
    *,
    directory: Path | None = None,
) -> bytes:
    """Read a library file by basename only (path traversal safe)."""
    safe = Path(filename).name
    if safe != filename or not safe.endswith(".json") or ".." in filename:
        raise ValueError(f"Invalid enrichment library filename: {filename}")
    root = (directory or default_enrichment_dir()).resolve()
    path = (root / safe).resolve()
    if not str(path).startswith(str(root)):
        raise ValueError(f"Invalid enrichment library filename: {filename}")
    if not path.is_file():
        raise FileNotFoundError(safe)
    return path.read_bytes()


def _library_file_meta(path: Path) -> dict[str, Any] | None:
    try:
        stat = path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
    except OSError:
        return None
    meta: dict[str, Any] = {
        "filename": path.name,
        "path": str(path),
        "size_bytes": stat.st_size,
        "modified_at": modified,
    }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        meta["valid"] = False
        return meta
    if not isinstance(data, dict) or not data.get("enrichment_version"):
        meta["valid"] = False
        return meta
    meta["valid"] = True
    meta["collector"] = data.get("collector")
    meta["collector_mode"] = data.get("collector_mode")
    meta["collected_at"] = data.get("collected_at")
    meta["material_count"] = data.get("material_count")
    bindings = data.get("bindings") or []
    if bindings and isinstance(bindings[0], dict):
        meta["target_ref"] = bindings[0].get("target_ref")
        meta["bind_required"] = bool(bindings[0].get("bind_required"))
    detected = data.get("detected") or {}
    if isinstance(detected, dict):
        meta["signals"] = detected.get("signals") or []
    return meta
