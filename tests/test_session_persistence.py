from __future__ import annotations

from samoyed.sessions import SessionStore


def test_session_persists_across_store_instances(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    first = SessionStore()
    record = first.load_sample_session("sample-lab")
    assert record.session_id == "sample-lab"

    second = SessionStore()
    loaded = second.get("sample-lab")
    assert loaded is not None
    assert loaded.caller_arn == record.caller_arn
    assert len(loaded.snapshot.nodes) == len(record.snapshot.nodes)

    paths = second.run_scenario("sample-lab", "leaked-credential")
    assert len(paths) >= 1
