"""Shared fixtures for tests — load field report JSON through the import pipeline."""

from __future__ import annotations

import pytest

from samoyed.sessions import SESSION_STORE


@pytest.fixture(autouse=True)
def _isolate_samoyed_home(tmp_path, monkeypatch):
    """Keep session files under the test tmp dir regardless of process cwd."""
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path / ".samoyed-home"))
    SESSION_STORE._sessions.clear()
    yield
    SESSION_STORE._sessions.clear()


@pytest.fixture
def isolated_sessions(tmp_path, monkeypatch):
    """Use a temp working directory so session persistence does not leak between tests."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path / ".samoyed-home"))
    yield SESSION_STORE


def load_fixture(session_store, fixture_id: str, *, session_id: str | None = None):
    """Import a catalog fixture and return the session id."""
    return session_store.load_fixture(fixture_id, session_id=session_id)
