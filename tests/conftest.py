"""Shared fixtures for tests — load field report JSON through the import pipeline."""

from __future__ import annotations

import pytest

from samoyed.sessions import SESSION_STORE


@pytest.fixture
def isolated_sessions(tmp_path, monkeypatch):
    """Use a temp working directory so session persistence does not leak between tests."""
    monkeypatch.chdir(tmp_path)
    yield SESSION_STORE


def load_fixture(session_store, fixture_id: str, *, session_id: str | None = None):
    """Import a catalog fixture and return the session id."""
    return session_store.load_fixture(fixture_id, session_id=session_id)
