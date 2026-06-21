from __future__ import annotations

from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.connectors.registry import import_report, list_connectors
from samoyed.path_engine.search import find_attack_paths
from samoyed.sessions import SESSION_STORE

FIXTURES = Path(__file__).parent / "fixtures"
client = TestClient(app)


def test_list_connectors_includes_file_importers():
    connectors = list_connectors()
    ids = {c["id"] for c in connectors}
    assert "iam-report" in ids
    assert "scoutsuite" in ids
    assert "cloudfox" in ids
    assert "aws-authz-details" in ids
    assert any(c["id"] == "iam-report" and c["file_import"] for c in connectors)


def test_iam_report_import_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (FIXTURES / "iam_report_minimal.json").read_bytes()
    record = SESSION_STORE.create_import_session("iam-report", payload)
    assert record.metadata["source"] == "iam-report"
    assert record.metadata["node_count"] >= 3

    start = SESSION_STORE.find_caller_node(record)
    assert start
    paths = find_attack_paths(
        record.snapshot,
        start_node_id=start,
        target_concept="SecretStore",
        max_depth=4,
    )
    assert paths
    assert any("CAN_ASSUME_ROLE" in [s.rel_type for s in p.steps] for p in paths)


def test_scoutsuite_import(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (FIXTURES / "scoutsuite_minimal.json").read_bytes()
    builder, meta = import_report("scoutsuite", payload, session_id="scout-test")
    assert meta["source"] == "scoutsuite"
    assert any("bob" in n.props.get("name", "") for n in builder.snapshot.nodes.values())


def test_cloudfox_import(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (FIXTURES / "cloudfox_minimal.json").read_bytes()
    record = SESSION_STORE.create_import_session("cloudfox", payload)
    assert record.metadata["source"] == "cloudfox"
    assert any("carol" in (n.props.get("display_name") or "") for n in record.snapshot.nodes.values())


def test_import_api_endpoint(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (FIXTURES / "iam_report_minimal.json").read_bytes()
    res = client.post(
        "/api/sessions/import",
        data={"connector": "iam-report"},
        files={"file": ("report.json", BytesIO(payload), "application/json")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["session_id"]
    assert body["metadata"]["source"] == "iam-report"

    graph = client.get(f"/api/sessions/{body['session_id']}/graph")
    assert graph.status_code == 200
    assert len(graph.json()["nodes"]) >= 3


def test_list_sessions_is_lightweight(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session(
        "cloudfox",
        (FIXTURES / "cloudfox_minimal.json").read_bytes(),
    )
    res = client.get("/api/sessions")
    assert res.status_code == 200
    data = res.json()
    match = next((s for s in data if s["session_id"] == record.session_id), None)
    assert match is not None
    assert match["metadata"].get("source") == "cloudfox"


def test_graph_query_end_id_contains(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_sample_session("graph-query-test")
    start = SESSION_STORE.find_caller_node(record)
    res = client.post(
        f"/api/sessions/{record.session_id}/graph/query",
        json={
            "start": start,
            "mode": "paths",
            "end_id_contains": "secrets",
            "max_depth": 6,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["paths"]
    assert any("secret" in str(p.get("target_match", {})).lower() for p in data["paths"])


def test_graph_query_rel_types_filter(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_sample_session("rel-filter-test")
    start = SESSION_STORE.find_caller_node(record)
    res = client.post(
        f"/api/sessions/{record.session_id}/graph/query",
        json={
            "start": start,
            "mode": "neighbors",
            "rel_types": ["CAN_ASSUME_ROLE"],
            "max_depth": 1,
        },
    )
    assert res.status_code == 200
    nodes = res.json().get("nodes") or []
    assert nodes
    assert all(n["rel_type"] == "CAN_ASSUME_ROLE" for n in nodes)
