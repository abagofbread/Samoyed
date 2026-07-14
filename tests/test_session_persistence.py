from __future__ import annotations

from samoyed.graph.persistence import default_samoyed_home, default_session_dir
from samoyed.sessions import SessionStore


def test_session_dir_defaults_under_home(tmp_path, monkeypatch):
    monkeypatch.delenv("SAMOYED_SESSION_DIR", raising=False)
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path / "home"))
    assert default_samoyed_home() == tmp_path / "home"
    assert default_session_dir() == tmp_path / "home" / "sessions"


def test_session_dir_explicit_override(tmp_path, monkeypatch):
    custom = tmp_path / "custom-sessions"
    monkeypatch.setenv("SAMOYED_SESSION_DIR", str(custom))
    assert default_session_dir() == custom


def test_session_persists_across_store_instances(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    first = SessionStore()
    record = first.load_fixture("lab-aws", session_id="fixture-lab")
    assert record.session_id == "fixture-lab"

    second = SessionStore()
    loaded = second.get("fixture-lab")
    assert loaded is not None
    assert loaded.caller_arn == record.caller_arn
    assert len(loaded.snapshot.nodes) == len(record.snapshot.nodes)

    paths = second.run_scenario("fixture-lab", "leaked-credential")
    assert len(paths) >= 1
