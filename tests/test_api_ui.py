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


def test_resolve_start_node_by_arn():
    record = SESSION_STORE.load_sample_session("ui-resolve-arn")
    caller_arn = "arn:aws:iam::111111111111:user/leaked-user"
    resolved = SESSION_STORE.resolve_start_node(record.session_id, caller_arn)
    assert resolved
    assert resolved.endswith("user/leaked-user")

    res = client.post(
        f"/api/sessions/{record.session_id}/paths/query",
        json={"start": caller_arn, "mode": "blast", "max_depth": 6},
    )
    assert res.status_code == 200
    assert len(res.json()["paths"]) >= 1


def test_blast_radius_by_principal_id():
    record = SESSION_STORE.load_sample_session("ui-blast-test")
    start = "Principal:arn:aws:iam::111111111111:user/leaked-user"
    res = client.post(
        f"/api/sessions/{record.session_id}/paths/query",
        json={"start": start, "mode": "blast", "max_depth": 6},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["start"] == start
    assert len(data["paths"]) >= 1


def test_create_sample_host_session():
    res = client.post("/api/sessions/sample-host")
    assert res.status_code == 200
    data = res.json()
    assert data["session_id"]
    assert data["caller_arn"] == "host:workstation:bob-laptop"
    assert data["metadata"]["scenario"] == "host-compromise"

    graph = client.get(f"/api/sessions/{data['session_id']}/graph")
    assert graph.status_code == 200
    nodes = graph.json()["nodes"]
    assert any(n.get("native_kind") == "CompromisedHost" for n in nodes)

    paths = client.post(
        f"/api/sessions/{data['session_id']}/paths/query",
        json={"start": "caller", "target_concept": "SecretStore", "max_depth": 8},
    )
    assert paths.status_code == 200
    assert paths.json()["paths"]
    assert max(len(p["steps"]) for p in paths.json()["paths"]) >= 3
