from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPORTS_DIR = Path(__file__).resolve().parent / "reports"


@dataclass(frozen=True)
class EnrichmentExampleSpec:
    id: str
    filename: str
    description: str
    lab_fixture: str
    collector: str
    collector_mode: str = "static"
    tags: tuple[str, ...] = ()


ENRICHMENT_EXAMPLES: tuple[EnrichmentExampleSpec, ...] = (
    EnrichmentExampleSpec(
        id="host-pivot-lab",
        filename="enrichment_host_pivot_lab.json",
        description="Full static collector bundle for the host-pivot lab (workstation repo + Lambda deploy config)",
        lab_fixture="host-pivot",
        collector="static-lab-bundle",
        tags=("host-pivot", "static-repo", "static-config", "demo"),
    ),
    EnrichmentExampleSpec(
        id="host-workstation-static",
        filename="enrichment_host_workstation_static.json",
        description="Static scan of Bob's developer workstation (AWS + Azure + kubeconfig)",
        lab_fixture="host-pivot",
        collector="static-repo",
        tags=("host-pivot", "static-repo"),
    ),
    EnrichmentExampleSpec(
        id="internal-tool-static",
        filename="enrichment_internal_tool_static.json",
        description="Static scan of internal-tool Lambda deploy config (.env.production)",
        lab_fixture="host-pivot",
        collector="static-config",
        tags=("host-pivot", "static-config", "lambda"),
    ),
)


def list_enrichment_examples() -> list[dict[str, Any]]:
    return [
        {
            "id": spec.id,
            "filename": spec.filename,
            "description": spec.description,
            "lab_fixture": spec.lab_fixture,
            "collector": spec.collector,
            "collector_mode": spec.collector_mode,
            "tags": list(spec.tags),
        }
        for spec in ENRICHMENT_EXAMPLES
    ]


def get_enrichment_example(example_id: str) -> EnrichmentExampleSpec:
    for spec in ENRICHMENT_EXAMPLES:
        if spec.id == example_id:
            return spec
    known = ", ".join(s.id for s in ENRICHMENT_EXAMPLES)
    raise KeyError(f"Unknown enrichment example '{example_id}'. Known: {known}")


def read_enrichment_example_bytes(example_id: str) -> bytes:
    spec = get_enrichment_example(example_id)
    path = REPORTS_DIR / spec.filename
    if not path.is_file():
        raise FileNotFoundError(f"Enrichment example file missing: {path}")
    return path.read_bytes()
