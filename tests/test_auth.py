from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from samoyed.api.auth import reset_auth_settings
from samoyed.api.main import app
from samoyed.sessions import SESSION_STORE


@pytest.fixture(autouse=True)
def clear_auth():
    reset_auth_settings()
    yield
    reset_auth_settings()


@pytest.fixture
def authed_client(monkeypatch):
    monkeypatch.setenv("SAMOYED_USERNAME", "admin")
    monkeypatch.setenv("SAMOYED_PASSWORD", "test-secret")
    reset_auth_settings()
    return TestClient(app)


def test_auth_disabled_allows_api_access(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = TestClient(app)
    res = client.get("/api/auth/status")
    assert res.status_code == 200
    assert res.json()["auth_required"] is False

    record = SESSION_STORE.load_fixture("lab-aws", session_id="auth-open-test")
    res = client.get(f"/api/sessions/{record.session_id}/graph")
    assert res.status_code == 200


def test_auth_required_blocks_api_without_credentials(authed_client):
    res = authed_client.get("/api/auth/status")
    assert res.status_code == 200
    assert res.json()["auth_required"] is True
    assert res.json()["authenticated"] is False

    res = authed_client.get("/api/sessions")
    assert res.status_code == 401


def test_login_grants_cookie_access(authed_client):
    bad = authed_client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert bad.status_code == 401

    res = authed_client.post("/api/auth/login", json={"username": "admin", "password": "test-secret"})
    assert res.status_code == 200
    assert res.json()["authenticated"] is True

    res = authed_client.get("/api/sessions")
    assert res.status_code == 200


def test_bearer_api_token(authed_client, monkeypatch):
    monkeypatch.setenv("SAMOYED_API_TOKEN", "machine-token")
    reset_auth_settings()
    client = TestClient(app)

    res = client.get("/api/sessions", headers={"Authorization": "Bearer machine-token"})
    assert res.status_code == 200

    res = client.get("/api/sessions", headers={"Authorization": "Bearer wrong"})
    assert res.status_code == 401


def test_logout_clears_session(authed_client):
    login = authed_client.post("/api/auth/login", json={"username": "admin", "password": "test-secret"})
    assert login.status_code == 200

    assert authed_client.get("/api/sessions").status_code == 200

    logout = authed_client.post("/api/auth/logout")
    assert logout.status_code == 200

    assert authed_client.get("/api/sessions").status_code == 401


def test_unauthenticated_root_redirects_to_login(authed_client):
    res = authed_client.get("/", follow_redirects=False)
    assert res.status_code == 302
    assert res.headers["location"] == "/login"


def test_login_page_is_public(authed_client):
    res = authed_client.get("/login")
    assert res.status_code == 200
    assert "Sign in" in res.text
