from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.collectors.assess import assess_text
from samoyed.collectors.static import collect_static_source
from samoyed.sessions import SESSION_STORE

client = TestClient(app)

FIXTURE_REPORT = Path(__file__).resolve().parents[1] / "samoyed/fixtures/reports/enrichment_host_pivot_lab.json"


def test_assess_text_finds_aws_key():
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=secret"
    materials = assess_text(text, path="app/.env")
    kinds = {m["kind"] for m in materials}
    assert "aws_access_key_env" in kinds
    assert "aws_secret_key_env" in kinds


def test_assess_text_finds_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    materials = assess_text(text, path="keys/id_rsa")
    assert any(m["kind"] == "generic_credential_file" for m in materials)


def test_collect_static_source_scans_repo(tmp_path):
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    (repo / "config.yaml").write_text("kind: Config\nclusters: []\n", encoding="utf-8")

    report = collect_static_source(
        repo,
        target_ref="LambdaFunction:internal-tool",
        collector_name="static-repo",
        resolves_to="arn:aws:iam::111111111111:user/dev-bob",
    )

    assert report["enrichment_version"] == 1
    assert report["collector"] == "static-repo"
    assert report["collector_mode"] == "static"
    assert report["files_scanned"] >= 2
    assert report["material_count"] >= 1
    binding = report["bindings"][0]
    assert binding["target_ref"] == "LambdaFunction:internal-tool"
    kinds = {m["kind"] for m in binding["materials"]}
    assert "aws_access_key_env" in kinds or "kubeconfig_file" in kinds
    for mat in binding["materials"]:
        if mat["kind"] != "none_observed":
            assert mat.get("resolves_to") == "arn:aws:iam::111111111111:user/dev-bob"


def test_collect_static_source_empty_dir(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    report = collect_static_source(empty, target_ref="host:lab-vm")
    assert report["bindings"][0]["materials"][0]["kind"] == "none_observed"


def test_enrich_api_without_target_node_id(tmp_path, monkeypatch):
    """Matches `samoyed enrich file.json` — bindings resolved via target_ref only."""
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("host-pivot", session_id="enrich-ref-only")
    res = client.post(
        f"/api/sessions/{record.session_id}/enrichment",
        files={"file": ("enrichment.json", FIXTURE_REPORT.read_bytes(), "application/json")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["stats"]["materials_applied"] == 6
    assert body["target_node_id"] is None
