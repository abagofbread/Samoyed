from __future__ import annotations

from pathlib import Path

from samoyed.cloud.concepts import ConceptType
from samoyed.collectors.static import collect_static_source
from samoyed.enrichment.apply import apply_enrichment_report
from samoyed.graph.builder import GraphBuilder


def test_apply_without_resolves_to_still_attaches_material(tmp_path: Path):
    """Default collect → apply path must create HAS_MATERIAL even without --resolves-to."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    report = collect_static_source(repo)  # unbound, no resolves_to

    builder = GraphBuilder("enrich-no-resolves")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:lab",
        props={"native_kind": "EC2Instance", "display_name": "lab"},
    )
    stats = apply_enrichment_report(builder, report, default_target_node_id=host)

    assert stats["bindings_applied"] == 1
    assert stats["materials_applied"] >= 1
    assert stats["skipped_materials"] == []
    assert any(p["kind"] == "aws_access_key_env" for p in stats["pending_unlocks"])

    has_material = [
        e
        for e in builder.snapshot.edges
        if e.src_id == host and e.rel_type == "HAS_MATERIAL"
    ]
    assert has_material
    mat = builder.snapshot.nodes[has_material[0].dst_id]
    assert mat.props.get("material_kind") == "aws_access_key_env"
    assert mat.props.get("unlock_pending") is True


def test_ui_target_overrides_baked_in_ref():
    builder = GraphBuilder("enrich-override")
    baked = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:old",
        props={"native_kind": "LambdaFunction"},
    )
    clicked = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:clicked",
        props={"native_kind": "EC2Instance"},
    )
    report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "bindings": [
            {
                "target_ref": "LambdaFunction:old",
                "materials": [
                    {
                        "kind": "aws_access_key_env",
                        "locator": ".env:AKIAIOSFODNN7EXAMPLE",
                        "confidence": "explicit",
                        "evidence": {},
                    }
                ],
            }
        ],
    }
    stats = apply_enrichment_report(builder, report, default_target_node_id=clicked)
    assert stats["hosts_updated"] == [clicked]
    assert any(e.src_id == clicked and e.rel_type == "HAS_MATERIAL" for e in builder.snapshot.edges)
    assert not any(e.src_id == baked and e.rel_type == "HAS_MATERIAL" for e in builder.snapshot.edges)
