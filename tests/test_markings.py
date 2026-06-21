from __future__ import annotations

import json

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def _cloudfox(account_id: str) -> bytes:
    return (
        f'{{"account_id":"{account_id}","findings":[{{"principal":"arn:aws:iam::{account_id}:user/x",'
        f'"resource":"S3Bucket:prod-db","capability":"reads"}}]}}'
    ).encode()


def test_mark_compromised_and_high_value(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id
    principal = "arn:aws:iam::123456789012:user/x"

    compromised = SESSION_STORE.mark_nodes(sid, [principal], compromised=True, source="test")
    assert len(compromised["marked"]) == 1
    assert compromised["marked"][0]["is_compromised"] is True

    high_value = SESSION_STORE.mark_nodes(sid, ["prod-db"], high_value=True, source="test")
    assert high_value["marked"][0]["is_high_value"] is True

    summary = SESSION_STORE.list_markings(sid)
    assert summary["compromised_count"] >= 1
    assert summary["high_value_count"] == 1


def test_resolve_compromised_alias(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id
    SESSION_STORE.mark_nodes(sid, ["arn:aws:iam::123456789012:user/x"], compromised=True)

    start = SESSION_STORE.resolve_start_node(sid, "compromised")
    assert start
    assert SESSION_STORE.get(sid).snapshot.nodes[start].props.get("is_compromised")


def test_blast_includes_marked_high_value(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id
    start = SESSION_STORE.resolve_start_node(sid, "arn:aws:iam::123456789012:user/x")
    SESSION_STORE.mark_nodes(sid, ["prod-db"], high_value=True)

    paths = SESSION_STORE.blast_radius(sid, start)
    targets = {p.target_match.get("node_id") for p in paths}
    marked = SESSION_STORE.list_markings(sid)["high_value"]
    assert marked
    assert any(m["node_id"] in targets for m in marked)


def test_mark_from_alert(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id
    result = SESSION_STORE.mark_from_alert(
        sid,
        compromised_refs=["arn:aws:iam::123456789012:user/x"],
        high_value_refs=["prod-db"],
    )
    assert result["compromised"]["marked"]
    assert result["high_value"]["marked"]


def test_api_markings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id

    res = client.post(
        f"/api/sessions/{sid}/markings",
        json={"refs": ["arn:aws:iam::123456789012:user/x"], "compromised": True},
    )
    assert res.status_code == 200
    assert res.json()["marked"][0]["is_compromised"] is True

    listing = client.get(f"/api/sessions/{sid}/markings")
    assert listing.status_code == 200
    assert listing.json()["compromised_count"] >= 1


def test_api_markings_alert(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id

    res = client.post(
        f"/api/sessions/{sid}/markings/alert",
        json={
            "compromised": ["arn:aws:iam::123456789012:user/x"],
            "high_value": ["prod-db"],
        },
    )
    assert res.status_code == 200


def test_mcp_mark_nodes(tmp_path, monkeypatch):
    pytest = __import__("pytest")
    pytest.importorskip("mcp")
    from samoyed.mcp import server as mcp_server

    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id

    out = mcp_server.mark_nodes(
        json.dumps(["arn:aws:iam::123456789012:user/x"]),
        session_id=sid,
        compromised=True,
    )
    data = json.loads(out)
    assert data["marked"][0]["is_compromised"] is True


def test_mcp_mark_from_alert(tmp_path, monkeypatch):
    pytest = __import__("pytest")
    pytest.importorskip("mcp")
    from samoyed.mcp import server as mcp_server

    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id

    out = mcp_server.mark_from_alert(
        json.dumps(
            {
                "compromised": ["arn:aws:iam::123456789012:user/x"],
                "high_value": ["prod-db"],
            }
        ),
        session_id=sid,
    )
    data = json.loads(out)
    assert data["compromised"]["marked"]
    assert data["high_value"]["marked"]


def test_mcp_list_markings(tmp_path, monkeypatch):
    pytest = __import__("pytest")
    pytest.importorskip("mcp")
    from samoyed.mcp import server as mcp_server

    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id
    SESSION_STORE.mark_nodes(sid, ["prod-db"], high_value=True)

    out = json.loads(mcp_server.list_markings(session_id=sid))
    assert out["high_value_count"] == 1


def test_paths_to_high_value_concept(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox("123456789012"))
    sid = record.session_id
    start = SESSION_STORE.resolve_start_node(sid, "arn:aws:iam::123456789012:user/x")
    SESSION_STORE.mark_nodes(sid, ["prod-db"], high_value=True)

    paths = SESSION_STORE.query_paths(sid, start_node_id=start, target_concept="high_value", max_depth=4)
    assert paths
