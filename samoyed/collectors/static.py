from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from samoyed.collectors.assess import assess_tree
from samoyed.enrichment.report import default_report

UNBOUND_TARGET_REF = "unbound"


def collect_static_source(
    root: Path,
    *,
    target_ref: str | None = None,
    collector_name: str = "static-repo",
    resolves_to: Optional[str] = None,
) -> dict[str, Any]:
    """
    Scan a repo or config directory and produce an enrichment report v1 document.

    Static collectors interview files only — no credentials are executed or validated.
    Binding to a graph node can be deferred: omit target_ref (writes ``unbound``) and
    pass ``--bind-ref`` / UI target when applying enrichment.
    """
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(root)

    materials, declared, scanned = assess_tree(root)
    if resolves_to:
        materials = [
            {**item, "resolves_to": resolves_to}
            if item.get("kind") != "none_observed"
            else item
            for item in materials
        ]

    if not materials:
        materials = [
            {
                "kind": "none_observed",
                "locator": str(root),
                "confidence": "explicit",
                "evidence": {"source_root": str(root), "files_scanned": scanned},
            }
        ]

    binding: dict[str, Any] = {
        "target_ref": target_ref or UNBOUND_TARGET_REF,
        "materials": materials,
    }
    if not target_ref:
        binding["bind_required"] = True

    report = default_report(
        collector=collector_name,
        collector_mode="static",
        bindings=[binding],
    )
    report["source_root"] = str(root)
    report["files_scanned"] = scanned
    report["material_count"] = len(materials)
    if declared:
        report["declared_resources"] = declared
    reuse = sum(1 for m in materials if int(m.get("reuse_count") or 0) > 1)
    if reuse:
        report["credential_reuse_findings"] = reuse
    return report
