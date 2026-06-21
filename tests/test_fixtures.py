from __future__ import annotations

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.fixtures.registry import FIXTURES, list_fixtures
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def test_fixture_catalog_lists_reports():
    catalog = list_fixtures()
    assert len(catalog) == len(FIXTURES)
    ids = {entry["id"] for entry in catalog}
    assert "lab-aws" in ids
    assert "enterprise-aws" in ids


def test_each_fixture_imports_through_connector_pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for spec in FIXTURES:
        record = SESSION_STORE.load_fixture(spec.id, session_id=f"fixture-{spec.id}")
        assert record.snapshot.nodes
        assert record.metadata.get("fixture_id") == spec.id
        assert record.metadata.get("source") in {spec.connector, "iam-report", "cloudfox", "aws-authz-details"}


def test_fixtures_api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = client.get("/api/fixtures")
    assert res.status_code == 200
    assert any(f["id"] == "lab-aws" for f in res.json())

    loaded = client.post("/api/sessions/fixtures/lab-aws")
    assert loaded.status_code == 200
    body = loaded.json()
    assert body["metadata"]["fixture_id"] == "lab-aws"
