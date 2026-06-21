from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.cloud.concepts import CloudProvider
from samoyed.session_naming import (
    build_session_id,
    derive_short_name,
    extract_scope_key,
    parse_session_id,
)
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def test_derive_short_name_from_aws_account():
    scope_key = extract_scope_key(
        CloudProvider.AWS,
        "123456789012",
        caller_arn="arn:aws:iam::123456789012:user/admin",
    )
    assert scope_key == "123456789012"
    assert derive_short_name(CloudProvider.AWS, scope_key) == "aws-123456789012"


def test_build_session_id_format():
    created = datetime(2025, 6, 19, 12, 0, tzinfo=timezone.utc)
    short_name = "aws-123456789012"
    session_id = build_session_id(short_name, created, "123456789012")
    assert session_id == "aws-123456789012_20250619_123456789012"
    parsed = parse_session_id(session_id)
    assert parsed == {
        "short_name": "aws-123456789012",
        "date": "20250619",
        "scope_key": "123456789012",
    }


def test_build_session_id_collision_suffix():
    created = datetime(2025, 6, 19, tzinfo=timezone.utc)
    existing = {"aws-1_20250619_1"}
    session_id = build_session_id("aws-1", created, "1", existing)
    assert session_id == "aws-1_20250619_1-2"


def test_import_session_uses_ergonomic_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox_payload("123456789012"))
    assert record.session_id.startswith("aws-123456789012_")
    assert record.metadata["short_name"] == "aws-123456789012"
    assert record.metadata["scope_key"] == "123456789012"


def _cloudfox_payload(account_id: str) -> bytes:
    return (
        f'{{"account_id":"{account_id}","findings":[{{"principal":"arn:aws:iam::{account_id}:user/x",'
        f'"resource":"S3Bucket:a","capability":"reads"}}]}}'
    ).encode()


def test_resolve_short_name_to_most_recent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    older = SESSION_STORE.create_import_session("cloudfox", _cloudfox_payload("999999999999"))
    newer = SESSION_STORE.create_import_session("cloudfox", _cloudfox_payload("123456789012"))
    assert older.session_id != newer.session_id

    resolved = SESSION_STORE.resolve_session_ref("aws-123456789012")
    assert resolved is not None
    assert resolved.session_id == newer.session_id


def test_blast_paths_without_session_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox_payload("123456789012"))
    start = "arn:aws:iam::123456789012:user/x"
    res = client.get("/api/paths/blast", params={"start": start})
    assert res.status_code == 200
    assert res.json()["session_id"] == record.session_id


def test_blast_paths_by_short_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox_payload("123456789012"))
    start = "arn:aws:iam::123456789012:user/x"
    res = client.get("/api/sessions/aws-123456789012/paths/blast", params={"start": start})
    assert res.status_code == 200
    assert res.json()["session_id"] == record.session_id


def test_scenario_run_without_session_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.create_import_session("cloudfox", _cloudfox_payload("123456789012"))
    start = "arn:aws:iam::123456789012:user/x"
    res = client.post("/api/scenarios/leaked-credential/run", params={"start": start})
    assert res.status_code == 200
    assert res.json()["session_id"] == record.session_id
