from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from samoyed.client.iam_report import collect_iam_report
from samoyed.credentials.aws import AwsCredential
from samoyed.firing_range.config import COMPOSE_FILE, LAB_ADMIN_ROLE, LAB_BUCKET, LAB_LAMBDA, LAB_SECRET, LAB_USER
from samoyed.firing_range.seed import load_leaked_credentials, ping_emulator, seed_aws_lab
from samoyed.path_engine.search import find_attack_paths
from samoyed.probes.runner import run_api_probes
from samoyed.sessions import SESSION_STORE

INTEGRATION = pytest.mark.integration


def localstack_reachable() -> bool:
    return ping_emulator(
        endpoint_url=os.environ.get("SAMOYED_FIRING_RANGE_ENDPOINT", "http://localhost:4566"),
        region=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if not localstack_reachable():
        pytest.skip("LocalStack not reachable — run: samoyed firing-range up && samoyed firing-range seed")

    tmp = tmp_path_factory.mktemp("firing-range")
    os.chdir(tmp)
    meta = seed_aws_lab(write_credentials=True)
    creds = load_leaked_credentials()
    yield {"meta": meta, "credentials": creds, "workdir": tmp}


@INTEGRATION
def test_bronze_multi_hop_attack_path(lab):
    from samoyed.firing_range.config import BRONZE_CHAIN_SECRET, BRONZE_PATH_BUCKET, BRONZE_PATH_SECRET

    cred = AwsCredential(
        access_key=lab["credentials"]["AccessKeyId"],
        secret_key=lab["credentials"]["SecretAccessKey"],
        region="us-east-1",
        endpoint_url=lab["credentials"]["endpoint_url"],
    )
    report = collect_iam_report(cred)
    record = SESSION_STORE.create_import_session(
        "iam-report",
        json.dumps(report).encode(),
        caller_arn=report["caller_arn"],
    )
    start = SESSION_STORE.find_caller_node(record)

    two_hop = find_attack_paths(record.snapshot, start_node_id=start, end_id_contains=BRONZE_PATH_SECRET, max_depth=4)
    assert two_hop and len(two_hop[0].steps) >= 2, "bronze 2-hop path to stale webhook secret"

    three_hop = find_attack_paths(
        record.snapshot, start_node_id=start, end_id_contains=BRONZE_CHAIN_SECRET, max_depth=5
    )
    assert three_hop and len(three_hop[0].steps) >= 3, "bronze 3-hop path via monitoring → lambda-exec"

    bucket_path = find_attack_paths(
        record.snapshot, start_node_id=start, end_id_contains=BRONZE_PATH_BUCKET, max_depth=4
    )
    assert bucket_path and len(bucket_path[0].steps) >= 2, "bronze 2-hop path to dead marketing bucket"


@INTEGRATION
def test_silver_multi_hop_attack_path(lab):
    from samoyed.firing_range.config import SILVER_DEV_BUCKET, SILVER_DEV_SECRET, SILVER_PROD_SECRET

    cred = AwsCredential(
        access_key=lab["credentials"]["AccessKeyId"],
        secret_key=lab["credentials"]["SecretAccessKey"],
        region="us-east-1",
        endpoint_url=lab["credentials"]["endpoint_url"],
    )
    report = collect_iam_report(cred)
    record = SESSION_STORE.create_import_session(
        "iam-report",
        json.dumps(report).encode(),
        caller_arn=report["caller_arn"],
    )
    start = SESSION_STORE.find_caller_node(record)

    dev_secret = find_attack_paths(
        record.snapshot, start_node_id=start, end_id_contains="hubspot-sandbox", max_depth=6
    )
    assert dev_secret and len(dev_secret[0].steps) >= 3, "silver 3-hop path to dev sandbox secret"

    dev_bucket = find_attack_paths(
        record.snapshot, start_node_id=start, end_id_contains=SILVER_DEV_BUCKET, max_depth=6
    )
    assert dev_bucket and len(dev_bucket[0].steps) >= 3, "silver 3-hop path to dev CI/CD artifacts"

    prod_paths = find_attack_paths(
        record.snapshot, start_node_id=start, end_id_contains=SILVER_PROD_SECRET, max_depth=6
    )
    assert not any(
        len(p.steps) >= 3 for p in prod_paths
    ), "prod payment secret should have no 3+ hop assume chain from leaked-user"


@INTEGRATION
def test_client_iam_report_from_live_apis(lab):
    cred = AwsCredential(
        access_key=lab["credentials"]["AccessKeyId"],
        secret_key=lab["credentials"]["SecretAccessKey"],
        region="us-east-1",
        endpoint_url=lab["credentials"]["endpoint_url"],
    )
    report = collect_iam_report(cred)
    assert report["collected_via"] == "live-aws-api"
    assert report["caller_arn"].endswith(f"user/{LAB_USER}")
    assert any(g["rel"] == "CAN_ASSUME_ROLE" for g in report["grants"])

    record = SESSION_STORE.create_import_session(
        "iam-report",
        json.dumps(report).encode(),
        caller_arn=report["caller_arn"],
    )
    start = SESSION_STORE.find_caller_node(record)
    paths = find_attack_paths(
        record.snapshot,
        start_node_id=start,
        end_id_contains=LAB_SECRET,
        max_depth=6,
    )
    assert paths, "Expected path from client iam-report to prod secret"


@INTEGRATION
def test_leaked_key_probe_session(lab):
    cred = AwsCredential(
        access_key=lab["credentials"]["AccessKeyId"],
        secret_key=lab["credentials"]["SecretAccessKey"],
        region="us-east-1",
        endpoint_url=lab["credentials"]["endpoint_url"],
    )
    probe_report = run_api_probes(cred)
    assert len(probe_report.allowed) >= 1
    allowed_ops = {r.operation for r in probe_report.allowed}
    assert "sts:GetCallerIdentity" in allowed_ops
    assert "s3:ListBuckets" in allowed_ops or "s3:ListAllMyBuckets" in allowed_ops

    record = SESSION_STORE.create_probe_session(cred, with_enum=False)
    assert record.metadata.get("enumeration_mode") == "probe"
    assert record.snapshot.nodes
    assert any(
        n.props.get("bucket_name") == LAB_BUCKET or LAB_BUCKET in str(n.props)
        for n in record.snapshot.nodes.values()
    )


@INTEGRATION
def test_aws_authz_real_api_import(lab):
    from samoyed.firing_range.aws_authz_export import export_account_authorization_details
    from samoyed.firing_range.config import DEFAULT_ACCESS_KEY, DEFAULT_SECRET_KEY

    payload = export_account_authorization_details(
        endpoint_url=lab["credentials"]["endpoint_url"],
        region="us-east-1",
        access_key=DEFAULT_ACCESS_KEY,
        secret_key=DEFAULT_SECRET_KEY,
    )
    assert payload.get("UserDetailList")
    assert any(u.get("UserName") == LAB_USER for u in payload["UserDetailList"])

    record = SESSION_STORE.create_import_session("aws-authz-details", json.dumps(payload).encode())
    assert record.metadata["source"] == "aws-authz-details"
    assert any(LAB_USER in str(n.props.get("name", "")) for n in record.snapshot.nodes.values())

    start = next(
        n.node_id
        for n in record.snapshot.nodes.values()
        if n.props.get("name") == LAB_USER or LAB_USER in str(n.props.get("arn", ""))
    )
    paths = find_attack_paths(
        record.snapshot,
        start_node_id=start,
        end_id_contains=LAB_ADMIN_ROLE,
        max_depth=4,
    )
    assert paths


def test_compose_file_exists():
    assert COMPOSE_FILE.is_file()


@patch("samoyed.firing_range.aws_helpers.aws_client")
def test_seed_aws_lab_creates_topology(mock_client_factory):
    iam = MagicMock()
    sts = MagicMock()
    s3 = MagicMock()
    secrets = MagicMock()
    lam = MagicMock()
    fallback = MagicMock()

    def factory(service: str, **kwargs):
        return {
            "iam": iam,
            "sts": sts,
            "s3": s3,
            "secretsmanager": secrets,
            "lambda": lam,
        }.get(service, fallback)

    mock_client_factory.side_effect = factory

    sts.get_caller_identity.return_value = {"Account": "000000000000"}
    iam.create_user.return_value = {}
    iam.create_role.return_value = {"Role": {"Arn": f"arn:aws:iam::000000000000:role/{LAB_ADMIN_ROLE}"}}
    iam.get_role.return_value = {"Role": {"Arn": f"arn:aws:iam::000000000000:role/{LAB_ADMIN_ROLE}"}}
    iam.create_access_key.return_value = {
        "AccessKey": {"AccessKeyId": "AKIA_LEAKED", "SecretAccessKey": "secret"}
    }
    secrets.create_secret.return_value = {
        "ARN": f"arn:aws:secretsmanager:us-east-1:000000000000:secret:{LAB_SECRET}"
    }
    lam.create_function.return_value = {
        "FunctionArn": f"arn:aws:lambda:us-east-1:000000000000:function:{LAB_LAMBDA}"
    }

    meta = seed_aws_lab(endpoint_url="http://localhost:4566", region="us-east-1", write_credentials=False)

    assert meta["account_id"] == "000000000000"
    assert meta["caller_arn"].endswith(f"user/{LAB_USER}")
    assert meta["bucket"] == LAB_BUCKET
    assert "clutter" in meta
    assert "bronze" in meta["clutter"]
    assert "silver" in meta["clutter"]
    iam.create_user.assert_called()
    iam.create_access_key.assert_called_once()
    lam.create_function.assert_called()


@patch("samoyed.firing_range.seed._client")
def test_ping_emulator(mock_client_factory):
    sts = MagicMock()
    mock_client_factory.return_value = sts
    sts.get_caller_identity.return_value = {"Account": "1"}
    assert ping_emulator(endpoint_url="http://localhost:4566") is True

    sts.get_caller_identity.side_effect = RuntimeError("down")
    assert ping_emulator(endpoint_url="http://localhost:4566") is False
