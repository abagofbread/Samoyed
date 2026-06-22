"""Unit tests for firing-range artifact collection."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from samoyed.cloud.concepts import CloudProvider
from samoyed.firing_range.collect import collect_firing_range_artifacts
from samoyed.probes.models import ProbeReport, ProbeResult


@pytest.fixture
def artifacts_home(tmp_path: Path, monkeypatch):
    root = tmp_path / ".samoyed" / "firing-range"
    root.mkdir(parents=True)
    creds = {
        "AccessKeyId": "AKIA_LEAKED",
        "SecretAccessKey": "secret",
        "region": "us-east-1",
        "endpoint_url": "http://localhost:4566",
        "user": "leaked-user",
    }
    (root / "leaked-user-credentials.json").write_text(json.dumps(creds), encoding="utf-8")
    (root / "seed-metadata.json").write_text(json.dumps({"account_id": "000000000000"}), encoding="utf-8")

    monkeypatch.setattr("samoyed.firing_range.collect.ARTIFACTS_DIR", root)
    monkeypatch.setattr("samoyed.firing_range.collect.ARTIFACT_SNAPSHOTS_DIR", root / "snapshots")
    monkeypatch.setattr("samoyed.firing_range.collect.LATEST_SNAPSHOT_DIR", root / "snapshots" / "latest")
    monkeypatch.setattr("samoyed.firing_range.collect.CREDENTIALS_FILE", root / "leaked-user-credentials.json")
    monkeypatch.setattr("samoyed.firing_range.collect.SEED_METADATA_FILE", root / "seed-metadata.json")
    monkeypatch.setattr("samoyed.firing_range.collect.CLIENT_IAM_REPORT_FILE", root / "client-iam-report.json")
    monkeypatch.setattr("samoyed.firing_range.collect.AWS_AUTHZ_FILE", root / "aws-authz-details.json")
    monkeypatch.setattr("samoyed.firing_range.collect.PROBE_REPORT_FILE", root / "probe-report.json")
    monkeypatch.setattr("samoyed.firing_range.collect.ACCOUNT_INVENTORY_FILE", root / "account-inventory.json")
    return root


@patch("samoyed.firing_range.collect.collect_account_inventory")
@patch("samoyed.firing_range.collect.run_api_probes")
@patch("samoyed.firing_range.collect.export_account_authorization_details")
@patch("samoyed.firing_range.collect.collect_iam_report")
def test_collect_firing_range_artifacts_writes_snapshot(
    mock_iam_report,
    mock_authz,
    mock_probes,
    mock_inventory,
    artifacts_home: Path,
):
    mock_iam_report.return_value = {
        "account_id": "000000000000",
        "caller_arn": "arn:aws:iam::000000000000:user/leaked-user",
        "identities": [{"arn": "x"}],
        "resources": [{"id": "r1"}, {"id": "r2"}],
        "grants": [{"action": "s3:ListBuckets"}],
    }
    mock_authz.return_value = {"UserDetailList": [{"UserName": "leaked-user"}], "RoleDetailList": [{"RoleName": "admin"}]}
    mock_probes.return_value = ProbeReport(
        provider=CloudProvider.AWS,
        caller_native_id="arn:aws:iam::000000000000:user/leaked-user",
        scope_id="000000000000",
        results=[
            ProbeResult(operation="s3:ListBuckets", status="allowed", resources=[]),
            ProbeResult(operation="iam:CreateUser", status="denied", resources=[]),
        ],
    )
    mock_inventory.return_value = {
        "s3_buckets": [{"name": "prod-data"}],
        "secrets": [{"name": "prod-db"}],
        "lambda_functions": [{"name": "vulnerable-handler"}],
    }

    manifest = collect_firing_range_artifacts(
        endpoint_url="http://localhost:4566",
        region="us-east-1",
        output_dir=artifacts_home / "snapshots" / "test-run",
    )

    snapshot = artifacts_home / "snapshots" / "test-run"
    assert snapshot.is_dir()
    assert (snapshot / "manifest.json").is_file()
    assert (snapshot / "client-iam-report.json").is_file()
    assert (snapshot / "aws-authz-details.json").is_file()
    assert (snapshot / "probe-report.json").is_file()
    assert (snapshot / "account-inventory.json").is_file()
    assert manifest["summary"]["iam_report_grants"] == 1
    assert manifest["summary"]["probe_allowed"] == 1
    assert (artifacts_home / "snapshots" / "latest" / "manifest.json").is_file()
    assert (artifacts_home / "client-iam-report.json").is_file()
