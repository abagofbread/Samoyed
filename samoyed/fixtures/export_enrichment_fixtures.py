"""Regenerate committed enrichment example JSON from collector sample directories."""

from __future__ import annotations

import json
from pathlib import Path

from samoyed.collectors.static import collect_static_source

SAMPLES = Path(__file__).resolve().parent / "collector_samples"
REPORTS = Path(__file__).resolve().parent / "reports"

DEV_BOB = "arn:aws:iam::111111111111:user/dev-bob"
AZURE_BOB = "azure:user:bob@corp.com"


def _apply_resolves_to(report: dict, *, target_ref: str) -> None:
    for binding in report.get("bindings") or []:
        for material in binding.get("materials") or []:
            kind = str(material.get("kind") or "")
            if kind == "none_observed":
                continue
            if kind.startswith("azure"):
                material["resolves_to"] = AZURE_BOB
            elif target_ref.startswith("LambdaFunction:"):
                material["resolves_to"] = DEV_BOB
            else:
                material["resolves_to"] = DEV_BOB


def main() -> None:
    workstation = collect_static_source(
        SAMPLES / "host-pivot-workstation",
        target_ref="host:workstation:bob-laptop",
        collector_name="static-repo",
    )
    _apply_resolves_to(workstation, target_ref="host:workstation:bob-laptop")
    for material in workstation["bindings"][0]["materials"]:
        if str(material.get("kind", "")).startswith("azure"):
            material["resolves_to"] = AZURE_BOB

    lambda_deploy = collect_static_source(
        SAMPLES / "internal-tool-deploy",
        target_ref="LambdaFunction:arn:aws:lambda:us-east-1:111111111111:function:internal-tool",
        collector_name="static-config",
        resolves_to=DEV_BOB,
    )

    combined = {
        "enrichment_version": 1,
        "collector": "static-lab-bundle",
        "collector_mode": "static",
        "collected_at": "2026-06-19T14:00:00Z",
        "description": "Example static collector output for the host-pivot lab (workstation repo + Lambda deploy config).",
        "lab_fixture": "host-pivot",
        "bindings": workstation["bindings"] + lambda_deploy["bindings"],
        "source_roots": [
            "samoyed/fixtures/collector_samples/host-pivot-workstation",
            "samoyed/fixtures/collector_samples/internal-tool-deploy",
        ],
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "enrichment_host_pivot_lab.json").write_text(
        json.dumps(combined, indent=2) + "\n",
        encoding="utf-8",
    )
    (REPORTS / "enrichment_host_workstation_static.json").write_text(
        json.dumps(
            {
                **workstation,
                "lab_fixture": "host-pivot",
                "description": "Static scan of Bob's workstation repo",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (REPORTS / "enrichment_internal_tool_static.json").write_text(
        json.dumps(
            {
                **lambda_deploy,
                "lab_fixture": "host-pivot",
                "description": "Static scan of internal-tool deploy config",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("Wrote enrichment fixtures to", REPORTS)


if __name__ == "__main__":
    main()
