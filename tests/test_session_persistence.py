from __future__ import annotations

from samoyed.sessions import SessionStore


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
