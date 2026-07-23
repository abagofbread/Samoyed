from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from samoyed.collectors.adapters import adapt_tool_report, load_json_payload
from samoyed.collectors.detect import CollectMode, DetectedSurface, detect_collect_target
from samoyed.collectors.on_host import collect_on_host
from samoyed.collectors.static import collect_static_source
from samoyed.enrichment.redact import redact_evidence, redact_secret_text


def _sanitize_report_materials(report: dict[str, Any]) -> dict[str, Any]:
    """Ensure locators/evidence never retain raw secret material."""
    for binding in report.get("bindings") or []:
        if not isinstance(binding, dict):
            continue
        materials = binding.get("materials") or []
        cleaned = []
        for material in materials:
            if not isinstance(material, dict):
                continue
            item = dict(material)
            if item.get("locator"):
                item["locator"] = redact_secret_text(str(item["locator"]))
            if item.get("evidence") is not None:
                item["evidence"] = redact_evidence(item.get("evidence") or {})
            cleaned.append(item)
        binding["materials"] = cleaned
    return report


def collect_target(
    target: str | Path,
    *,
    mode: CollectMode | None = None,
    target_ref: str | None = None,
    resolves_to: Optional[str] = None,
    ingest_reports: list[Path] | None = None,
    collector_name: str | None = None,
) -> dict[str, Any]:
    """
    Implicit collect entrypoint: detect surface, run built-in assessors, consolidate
    optional external tool reports into one enrichment document.
    """
    surface = detect_collect_target(target, mode=mode)
    if surface.mode == "on-host":
        report = collect_on_host(
            target_ref=target_ref,
            root=surface.root,
            resolves_to=resolves_to,
        )
    else:
        report = collect_static_source(
            surface.root,
            target_ref=target_ref,
            collector_name=collector_name or _static_collector_name(surface),
            resolves_to=resolves_to,
        )

    report["detected"] = {
        "mode": surface.mode,
        "signals": list(surface.signals),
        "suggested_adapters": list(surface.suggested_adapters),
        "notes": list(surface.notes),
    }

    if ingest_reports:
        merged = _merge_ingested_reports(
            report,
            ingest_reports,
            resolves_to=resolves_to,
        )
        report = merged

    return _sanitize_report_materials(report)

def _static_collector_name(surface: DetectedSurface) -> str:
    if "terraform" in surface.signals:
        return "static-repo"
    if "kubernetes" in surface.signals or "docker" in surface.signals:
        return "static-config"
    return "static-repo"


def _merge_ingested_reports(
    report: dict[str, Any],
    paths: list[Path],
    *,
    resolves_to: Optional[str],
) -> dict[str, Any]:
    bindings = list(report.get("bindings") or [])
    if not bindings:
        bindings = [{"target_ref": "unbound", "bind_required": True, "materials": []}]

    materials = list(bindings[0].get("materials") or [])
    # Drop none_observed placeholder when real findings arrive
    materials = [m for m in materials if m.get("kind") != "none_observed"]

    ingested_meta: list[dict[str, Any]] = []
    for path in paths:
        payload = load_json_payload(path)
        try:
            found = adapt_tool_report(payload, source_label=str(path))
        except ValueError as exc:
            raise ValueError(f"{path}: {exc}") from exc
        for item in found:
            if resolves_to and item.get("kind") != "none_observed":
                item = {**item, "resolves_to": resolves_to}
            materials.append(item)
        ingested_meta.append({"path": str(path), "materials": len(found)})

    if not materials:
        materials = [
            {
                "kind": "none_observed",
                "locator": report.get("source_root") or "ingest",
                "confidence": "explicit",
                "evidence": {"ingested_reports": ingested_meta},
            }
        ]

    bindings[0]["materials"] = _dedupe(materials)
    report["bindings"] = bindings
    report["material_count"] = len(bindings[0]["materials"])
    report["ingested_reports"] = ingested_meta
    # Prefer consolidated label when tool reports were merged
    if ingested_meta:
        report["collector"] = "consolidated"
    return report


def _dedupe(materials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in materials:
        key = (str(item.get("kind")), str(item.get("locator")))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
