from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.enrichment.apply import apply_enrichment_report
from samoyed.enrichment.catalog import export_catalog
from samoyed.graph.builder import GraphBuilder
from samoyed.path_engine.search import find_attack_paths
from samoyed.sessions import SESSION_STORE

client = TestClient(app)

FIXTURE_REPORT = Path(__file__).resolve().parents[1] / "samoyed/fixtures/reports/enrichment_host_pivot_lab.json"
LAMBDA_ONLY_REPORT = Path(__file__).resolve().parents[1] / "samoyed/fixtures/reports/enrichment_internal_tool_static.json"


def _host_pivot_snapshot(tmp_path, monkeypatch, session_id: str = "enrich-lab"):
    monkeypatch.chdir(tmp_path)
    return SESSION_STORE.load_fixture("host-pivot", session_id=session_id).snapshot


def test_export_catalog_lists_material_kinds():
    catalog = export_catalog()
    kinds = {item["kind"] for item in catalog["material_kinds"]}
    assert "aws_access_key_env" in kinds
    assert "k8s_service_account_token" in kinds
    assert "none_observed" in kinds


def test_apply_enrichment_extends_blast_radius(tmp_path, monkeypatch):
    snapshot = _host_pivot_snapshot(tmp_path, monkeypatch)
    builder = GraphBuilder("enrich-test")
    builder.snapshot = snapshot
    payload = json.loads(LAMBDA_ONLY_REPORT.read_text())
    stats = apply_enrichment_report(builder, payload)
    assert stats["bindings_applied"] == 1
    assert stats["materials_applied"] == 2
    assert stats["edges_added"] >= 2

    lambda_node = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if "internal-tool" in str(n.props.get("native_id", ""))
    )
    dev_bob = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if str(n.props.get("native_id", "")).endswith("user/dev-bob")
    )
    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=lambda_node,
        end_node_id=dev_bob,
        max_depth=6,
    )
    assert paths
    rels = [s.rel_type for s in paths[0].steps]
    assert "HAS_MATERIAL" in rels
    assert "UNLOCKS" in rels


def test_apply_enrichment_to_node_without_target_ref(tmp_path, monkeypatch):
    snapshot = _host_pivot_snapshot(tmp_path, monkeypatch)
    builder = GraphBuilder("enrich-node")
    builder.snapshot = snapshot
    lambda_node = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if "internal-tool" in str(n.props.get("native_id", ""))
    )
    report = {
        "enrichment_version": 1,
        "collector": "on-host-fs",
        "collector_mode": "on-host",
        "bindings": [
            {
                "materials": [
                    {
                        "kind": "none_observed",
                        "locator": "~/.aws",
                        "confidence": "explicit",
                    }
                ]
            }
        ],
    }
    stats = apply_enrichment_report(builder, report, default_target_node_id=lambda_node)
    assert stats["bindings_applied"] == 1
    node = builder.snapshot.nodes[lambda_node]
    assert node.props.get("enrichment_status") == "clean"


def test_session_store_apply_enrichment_persists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("host-pivot", session_id="enrich-store")
    lambda_node = next(
        nid
        for nid, n in record.snapshot.nodes.items()
        if "internal-tool" in str(n.props.get("native_id", ""))
    )
    stats = SESSION_STORE.apply_enrichment(
        record.session_id,
        FIXTURE_REPORT.read_bytes(),
    )
    assert stats["bindings_applied"] == 2
    assert stats["materials_applied"] >= 4
    reloaded = SESSION_STORE.get(record.session_id)
    assert reloaded.metadata.get("enrichment_runs")


def test_apply_enrichment_api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("host-pivot", session_id="enrich-api")
    lambda_node = next(
        nid
        for nid, n in record.snapshot.nodes.items()
        if "internal-tool" in str(n.props.get("native_id", ""))
    )
    res = client.post(
        f"/api/sessions/{record.session_id}/enrichment",
        files={"file": ("enrichment.json", LAMBDA_ONLY_REPORT.read_bytes(), "application/json")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["stats"]["materials_applied"] == 2


def test_enrichment_catalog_api():
    res = client.get("/api/enrichment/catalog")
    assert res.status_code == 200
    assert res.json()["enrichment_version"] == 1


def test_enrichment_examples_api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("host-pivot", session_id="enrich-example-api")
    examples = client.get("/api/enrichment/examples")
    assert examples.status_code == 200
    ids = {item["id"] for item in examples.json()}
    assert "host-pivot-lab" in ids

    res = client.post(f"/api/sessions/{record.session_id}/enrichment/examples/host-pivot-lab")
    assert res.status_code == 200
    body = res.json()
    assert body["stats"]["bindings_applied"] == 2
    assert body["stats"]["materials_applied"] >= 4


def _node_ids(snapshot, *, needle: str) -> list[str]:
    return [
        nid
        for nid, node in snapshot.nodes.items()
        if needle in str(node.props.get("native_id", ""))
    ]


def test_subsequent_enrichment_updates_only_affected_hosts(tmp_path, monkeypatch):
    snapshot = _host_pivot_snapshot(tmp_path, monkeypatch)
    builder = GraphBuilder("enrich-sequential")
    builder.snapshot = snapshot

    workstation_report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "bindings": [
            {
                "target_ref": "host:workstation:bob-laptop",
                "materials": [
                    {
                        "kind": "aws_access_key_env",
                        "locator": ".env:AKIAIOSFODNN7EXAMPLE",
                        "resolves_to": "arn:aws:iam::111111111111:user/dev-bob",
                        "confidence": "explicit",
                    }
                ],
            }
        ],
    }
    apply_enrichment_report(builder, workstation_report)

    host_id = _node_ids(builder.snapshot, needle="bob-laptop")[0]
    lambda_id = _node_ids(builder.snapshot, needle="internal-tool")[0]
    host = builder.snapshot.nodes[host_id]
    lambda_node = builder.snapshot.nodes[lambda_id]

    assert host.props.get("enrichment_status") == "material_found"
    assert lambda_node.props.get("enrichment_status") is None

    apply_enrichment_report(builder, json.loads(LAMBDA_ONLY_REPORT.read_text()))

    assert builder.snapshot.nodes[host_id].props.get("enrichment_status") == "material_found"
    assert builder.snapshot.nodes[lambda_id].props.get("enrichment_status") == "material_found"


def test_reapply_enrichment_replaces_host_materials(tmp_path, monkeypatch):
    snapshot = _host_pivot_snapshot(tmp_path, monkeypatch)
    builder = GraphBuilder("enrich-replace")
    builder.snapshot = snapshot
    lambda_id = _node_ids(builder.snapshot, needle="internal-tool")[0]

    first = {
        "enrichment_version": 1,
        "collector": "static-config",
        "collector_mode": "static",
        "bindings": [
            {
                "target_ref": "LambdaFunction:arn:aws:lambda:us-east-1:111111111111:function:internal-tool",
                "materials": [
                    {
                        "kind": "aws_access_key_env",
                        "locator": ".env.old:key",
                        "resolves_to": "arn:aws:iam::111111111111:user/dev-bob",
                        "confidence": "explicit",
                    }
                ],
            }
        ],
    }
    apply_enrichment_report(builder, first)
    old_materials = [
        nid
        for nid, node in builder.snapshot.nodes.items()
        if node.props.get("native_kind") == "PivotMaterial"
        and node.props.get("locator") == ".env.old:key"
    ]
    assert len(old_materials) == 1

    second = {
        "enrichment_version": 1,
        "collector": "static-config",
        "collector_mode": "static",
        "bindings": [
            {
                "target_ref": "LambdaFunction:arn:aws:lambda:us-east-1:111111111111:function:internal-tool",
                "materials": [
                    {
                        "kind": "none_observed",
                        "locator": "deploy/",
                        "confidence": "explicit",
                    }
                ],
            }
        ],
    }
    stats = apply_enrichment_report(builder, second)
    assert stats["materials_removed"] == 1
    assert old_materials[0] not in builder.snapshot.nodes
    assert builder.snapshot.nodes[lambda_id].props.get("enrichment_status") == "clean"

    has_material_edges = [
        edge
        for edge in builder.snapshot.edges
        if edge.src_id == lambda_id and edge.rel_type == "HAS_MATERIAL"
    ]
    assert not has_material_edges

