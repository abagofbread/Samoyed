from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from samoyed.api.auth import reset_auth_settings
from samoyed.api.main import app
from samoyed.graph.persistence import default_session_dir
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_auth():
    reset_auth_settings()
    yield
    reset_auth_settings()


def test_delete_session_removes_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session(
        "cloudfox",
        b'{"account_id":"1","findings":[{"principal":"arn:aws:iam::1:user/x","resource":"S3Bucket:a","capability":"reads"}]}',
    )
    path = default_session_dir() / f"{record.session_id}.json"
    assert path.is_file()

    res = client.delete(f"/api/sessions/{record.session_id}")
    assert res.status_code == 200
    assert res.json()["deleted"] is True
    assert not path.is_file()
    assert SESSION_STORE.get(record.session_id) is None


def test_delete_demo_session_blocked_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("lab-aws", session_id="fixture-lab-aws")

    res = client.delete(f"/api/sessions/{record.session_id}")
    assert res.status_code == 403

    res = client.delete(f"/api/sessions/{record.session_id}?include_demo=true")
    assert res.status_code == 200
    assert res.json()["deleted"] is True


def test_clear_sessions_keeps_demos(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    imported = SESSION_STORE.create_import_session(
        "cloudfox",
        b'{"account_id":"1","findings":[{"principal":"arn:aws:iam::1:user/x","resource":"S3Bucket:a","capability":"reads"}]}',
    )
    demo = SESSION_STORE.load_fixture("lab-aws", session_id="fixture-lab-aws")

    res = client.post("/api/sessions/clear", json={"confirm": "clear-sessions"})
    assert res.status_code == 200
    body = res.json()
    assert imported.session_id in body["deleted"]
    assert demo.session_id in body["skipped"]
    assert SESSION_STORE.get(imported.session_id) is None
    assert SESSION_STORE.get(demo.session_id) is not None


def test_clear_sessions_requires_confirm(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = client.post("/api/sessions/clear", json={"confirm": "nope"})
    assert res.status_code == 400


def test_clear_sessions_requires_auth_when_enabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SAMOYED_USERNAME", "admin")
    monkeypatch.setenv("SAMOYED_PASSWORD", "test-secret")
    reset_auth_settings()
    authed = TestClient(app)

    res = client.post("/api/sessions/clear", json={"confirm": "clear-sessions"})
    assert res.status_code == 401

    login = authed.post("/api/auth/login", json={"username": "admin", "password": "test-secret"})
    assert login.status_code == 200
    res = authed.post("/api/sessions/clear", json={"confirm": "clear-sessions"})
    assert res.status_code == 200
