from __future__ import annotations

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.sessions import SESSION_STORE, is_demo_session

client = TestClient(app)


def test_is_demo_session_detects_samples():
    assert is_demo_session("sample-lab", {"sample": True})
    assert is_demo_session("sample-enterprise", {})
    assert not is_demo_session("a43f7186-1e9d-42f0-beb2-e5ba459aaa69", {"source": "cloudfox"})


def test_list_sessions_recent_excludes_demos(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    SESSION_STORE.create_import_session(
        "cloudfox",
        b'{"account_id":"1","findings":[{"principal":"arn:aws:iam::1:user/x","resource":"S3Bucket:a","capability":"reads"}]}',
    )
    SESSION_STORE.load_sample_session("sample-lab")

    recent = client.get("/api/sessions?scope=recent&limit=1")
    assert recent.status_code == 200
    data = recent.json()
    assert len(data) == 1
    assert not data[0].get("is_demo")
    assert data[0]["session_id"] != "sample-lab"

    all_resp = client.get("/api/sessions?scope=all")
    assert all_resp.status_code == 200
    ids = {s["session_id"] for s in all_resp.json()}
    assert "sample-lab" not in ids

    with_demos = client.get("/api/sessions?scope=all&include_demos=true")
    assert "sample-lab" in {s["session_id"] for s in with_demos.json()}


def test_list_sessions_by_ids(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_sample_enterprise_session("sample-enterprise")

    res = client.get(f"/api/sessions?scope=ids&ids={record.session_id}")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["session_id"] == "sample-enterprise"
    assert data[0]["is_demo"] is True


def test_list_sessions_ids_requires_parameter():
    res = client.get("/api/sessions?scope=ids")
    assert res.status_code == 400
