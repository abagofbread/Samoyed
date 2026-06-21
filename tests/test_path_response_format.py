from __future__ import annotations

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.path_engine.format import format_path_query_response
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def test_format_path_query_response_summary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("lab-aws", session_id="format-test")
    start = SESSION_STORE.find_caller_node(record)
    raw = {
        "paths": [
            {
                "path_id": "abc",
                "score": 0.9,
                "node_ids": [start, "x", "y"],
                "target_match": {"concept_type": "SecretStore", "resource_type": "Secret", "node_id": "y"},
                "steps": [
                    {"step": 0, "src": start, "rel": "CAN_ASSUME_ROLE", "dst": "x"},
                    {"step": 1, "src": "x", "rel": "READS", "dst": "y"},
                ],
            }
        ]
    }
    out = format_path_query_response(
        session_id=record.session_id,
        graph=record.snapshot,
        start_node_id=start,
        mode="blast",
        raw=raw,
    )
    assert out["summary"]["path_count"] == 1
    assert out["summary"]["by_target_concept"]["SecretStore"] == 1
    assert out["paths"][0]["chain"]
    assert out["paths"][0]["relations"] == ["CAN_ASSUME_ROLE", "READS"]
    assert out["targets"][0]["concept"] == "SecretStore"


def test_blast_get_jq_friendly(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("lab-aws", session_id="jq-blast-test")
    start = SESSION_STORE.find_caller_node(record)
    res = client.get(
        f"/api/sessions/{record.session_id}/paths/blast",
        params={"start": start, "max_depth": 6},
    )
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "targets" in data
    assert data["paths"][0].get("chain")
    assert data["session_id"] == record.session_id


def test_paths_query_post_includes_summary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("lab-aws", session_id="jq-post-test")
    res = client.post(
        f"/api/sessions/{record.session_id}/paths/query",
        json={"start": "caller", "mode": "blast", "max_depth": 6},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]["path_count"] >= 1
    secrets = [t for t in data["targets"] if t.get("concept") == "SecretStore"]
    assert secrets
