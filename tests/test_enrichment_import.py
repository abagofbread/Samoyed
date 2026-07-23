"""Enrichment import: fuzzy auto-bind + idempotent re-import."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.cloud.concepts import ConceptType
from samoyed.collectors.static import collect_static_source
from samoyed.enrichment.apply import apply_enrichment_report
from samoyed.graph.builder import GraphBuilder
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def _report_with_key(*, target_ref: str = "unbound", resolves_to: str | None = None, name_hints=None):
    mat = {
        "kind": "aws_access_key_env",
        "locator": ".env:AKIA****************",
        "confidence": "explicit",
        "evidence": {},
    }
    if resolves_to:
        mat["resolves_to"] = resolves_to
    if name_hints:
        mat["name_hints"] = name_hints
    return {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "source_root": "/tmp/bastion-lab",
        "host_hint": "bastion-01",
        "bindings": [
            {
                "target_ref": target_ref,
                "materials": [mat],
            }
        ],
    }


def test_import_fuzzy_matches_host_by_hint():
    builder = GraphBuilder("enrich-fuzzy-host")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:i-bastion",
        props={
            "native_kind": "EC2Instance",
            "resource_type": "EC2Instance",
            "display_name": "bastion-01",
            "name": "bastion-01",
        },
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/dev-bob",
        props={"name": "dev-bob", "resource_type": "Role"},
    )
    report = _report_with_key(target_ref="unbound", name_hints=["dev-bob"])
    stats = apply_enrichment_report(builder, report)

    assert stats["materials_applied"] == 1
    assert stats["hosts_updated"] == [host]
    assert stats["unlocks_applied"] == 1
    assert any(e.src_id == host and e.rel_type == "HAS_MATERIAL" for e in builder.snapshot.edges)
    assert any(e.rel_type == "UNLOCKS" and e.dst_id == role for e in builder.snapshot.edges)


def test_reimport_is_idempotent():
    builder = GraphBuilder("enrich-reimport")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:lab",
        props={"resource_type": "EC2Instance", "name": "bastion-01", "display_name": "bastion-01"},
    )
    report = _report_with_key(target_ref="bastion-01")

    first = apply_enrichment_report(builder, report)
    mats_after_first = [
        n for n in builder.snapshot.nodes.values() if n.props.get("material_kind") == "aws_access_key_env"
    ]
    assert first["materials_applied"] == 1
    assert len(mats_after_first) == 1

    second = apply_enrichment_report(builder, report)
    mats_after_second = [
        n for n in builder.snapshot.nodes.values() if n.props.get("material_kind") == "aws_access_key_env"
    ]
    assert second["materials_applied"] == 1
    assert second["materials_removed"] >= 1
    assert len(mats_after_second) == 1
    has_material = [e for e in builder.snapshot.edges if e.src_id == host and e.rel_type == "HAS_MATERIAL"]
    assert len(has_material) == 1


def test_hostless_import_still_unlocks_identity():
    builder = GraphBuilder("enrich-hostless")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/alice",
        props={"name": "alice", "resource_type": "User"},
    )
    report = _report_with_key(target_ref="unbound", resolves_to="alice")
    report.pop("host_hint", None)
    report["source_root"] = "/tmp/unknown-box"
    stats = apply_enrichment_report(builder, report)
    assert stats["materials_applied"] == 1
    assert stats["hostless_bindings"] == 1
    assert stats["unlocks_applied"] == 1
    assert any(e.rel_type == "UNLOCKS" and e.dst_id == role for e in builder.snapshot.edges)
    assert not any(e.rel_type == "HAS_MATERIAL" for e in builder.snapshot.edges)


def test_collect_then_import_without_bind(tmp_path: Path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / ".env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    report = collect_static_source(repo)
    report["host_hint"] = "lab-vm"

    builder = GraphBuilder("enrich-collect-import")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:lab-vm",
        props={"resource_type": "EC2Instance", "name": "lab-vm", "display_name": "lab-vm"},
    )
    stats = apply_enrichment_report(builder, report)
    assert stats["materials_applied"] >= 1
    assert host in stats["hosts_updated"]


def test_library_import_without_selected_node(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_ENRICHMENT_DIR", str(tmp_path))
    report = _report_with_key(target_ref="bob-laptop", name_hints=[])
    report["host_hint"] = "bob-laptop"
    (tmp_path / "keys.json").write_text(json.dumps(report), encoding="utf-8")

    record = SESSION_STORE.load_fixture("host-pivot", session_id="enrich-lib-autofuzzy")
    res = client.post(f"/api/sessions/{record.session_id}/enrichment/library/keys.json")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["stats"]["materials_applied"] >= 1


def test_enrich_session_surface_endpoint():
    record = SESSION_STORE.load_fixture("host-pivot", session_id="enrich-surface-api")
    res = client.post(f"/api/sessions/{record.session_id}/enrich-surface")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["session_id"] == record.session_id
    assert "stats" in body
    assert isinstance(body["stats"], dict)
