from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from samoyed.collectors.assess import assess_file, iter_static_files
from samoyed.enrichment.report import default_report


def collect_static_source(
    root: Path,
    *,
    target_ref: str,
    collector_name: str = "static-repo",
    resolves_to: Optional[str] = None,
) -> dict[str, Any]:
    """
    Scan a repo or config directory and produce an enrichment report v1 document.

    Static collectors interview files only — no credentials are executed or validated.
    """
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(root)

    materials: list[dict[str, Any]] = []
    scanned = 0
    path_root = root if root.is_dir() else root.parent
    for path in iter_static_files(root):
        scanned += 1
        try:
            rel = str(path.relative_to(path_root))
        except ValueError:
            rel = path.name
        for item in assess_file(path, display_path=rel):
            if resolves_to and item["kind"] != "none_observed":
                item = {**item, "resolves_to": resolves_to}
            materials.append(item)

    if not materials:
        materials = [
            {
                "kind": "none_observed",
                "locator": str(root),
                "confidence": "explicit",
                "evidence": {"source_root": str(root), "files_scanned": scanned},
            }
        ]

    report = default_report(
        collector=collector_name,
        collector_mode="static",
        bindings=[
            {
                "target_ref": target_ref,
                "materials": materials,
            }
        ],
    )
    report["source_root"] = str(root)
    report["files_scanned"] = scanned
    report["material_count"] = len(materials)
    return report
