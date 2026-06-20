from __future__ import annotations

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.sessions import SESSION_STORE


client = TestClient(app)


def test_search_suggestions_for_k8s_sample():
    record = SESSION_STORE.load_sample_k8s_session("ui-k8s-suggest")
    res = client.get(f"/api/sessions/{record.session_id}/search-suggestions")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 5
    assert any(s["id"] == "paths-to-secrets" for s in data)


def test_patch_node_properties(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_sample_session("ui-patch-test")
    node_id = next(
        n.node_id for n in record.snapshot.nodes.values() if n.props.get("is_caller")
    )
    res = client.patch(
        f"/api/sessions/{record.session_id}/nodes",
        json={"node_id": node_id, "properties": {"analyst_note": "high risk", "tier": 1}},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["analyst_note"] == "high risk"
    assert body["tier"] == 1

    reloaded = SESSION_STORE.get(record.session_id)
    assert reloaded.snapshot.nodes[node_id].props["analyst_note"] == "high risk"


def test_paths_query_post():
    record = SESSION_STORE.load_sample_session("ui-paths-test")
    res = client.post(
        f"/api/sessions/{record.session_id}/paths/query",
        json={"start": "caller", "target_concept": "SecretStore", "max_depth": 4},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["paths"]
    assert data["start"]
