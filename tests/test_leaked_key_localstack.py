"""
Real leaked API key probe test against LocalStack.

No Samoyed session files, no SESSION_STORE, no offline sample graphs.
Credentials come from IAM create_access_key during seed; probes hit live APIs.
"""
from __future__ import annotations

import json
import os

import pytest

from samoyed.credentials.aws import AwsCredential
from samoyed.firing_range.config import LAB_BUCKET, LAB_SECRET, LAB_USER
from samoyed.firing_range.seed import load_leaked_credentials, ping_emulator, seed_aws_lab
from samoyed.probes.runner import run_api_probes

pytestmark = pytest.mark.integration

ENDPOINT = os.environ.get("SAMOYED_FIRING_RANGE_ENDPOINT", "http://localhost:4566")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(scope="module")
def leaked_key_lab(tmp_path_factory):
    if not ping_emulator(endpoint_url=ENDPOINT, region=REGION):
        pytest.skip(f"LocalStack not reachable at {ENDPOINT}")

    work = tmp_path_factory.mktemp("leaked-key-live")
    os.chdir(work)
    meta = seed_aws_lab(endpoint_url=ENDPOINT, region=REGION, write_credentials=True)
    leaked = load_leaked_credentials()
    return {"meta": meta, "leaked": leaked}


def test_leaked_api_key_probe_live_localstack(leaked_key_lab):
    """Probe catalog with a real IAM access key — no session persistence."""
    leaked = leaked_key_lab["leaked"]
    assert leaked["AccessKeyId"] != "test", "must use per-user key, not LocalStack admin"

    cred = AwsCredential(
        access_key=leaked["AccessKeyId"],
        secret_key=leaked["SecretAccessKey"],
        region=REGION,
        endpoint_url=ENDPOINT,
    )

    identity = cred.get_caller_identity()
    assert identity["Arn"].endswith(f"user/{LAB_USER}")

    report = run_api_probes(cred)
    allowed_ops = {r.operation for r in report.allowed}

    # Core recon that leaked-user's recon-read policy grants
    assert "sts:GetCallerIdentity" in allowed_ops
    assert "s3:ListBuckets" in allowed_ops or "s3:ListAllMyBuckets" in allowed_ops
    assert "secretsmanager:ListSecrets" in allowed_ops
    assert "lambda:ListFunctions" in allowed_ops
    assert "iam:ListUsers" in allowed_ops
    assert "ec2:DescribeInstances" in allowed_ops

    # Must not have discovered admin-level attach or assume without target
    assert "iam:ListAttachedUserPolicies" not in allowed_ops

    # Services not in recon-read policy should stay denied or error
    assert "rds:DescribeDBInstances" not in allowed_ops

    # Verify we actually got resource names back from live APIs
    s3_probe = next(r for r in report.allowed if r.operation.startswith("s3:List"))
    bucket_names = {b.get("name") for b in s3_probe.resources}
    assert LAB_BUCKET in bucket_names

    secrets_probe = next(r for r in report.allowed if r.operation == "secretsmanager:ListSecrets")
    secret_names = {s.get("name") for s in secrets_probe.resources}
    assert LAB_SECRET in secret_names

    # Emit structured report for CI logs (not a session file)
    summary = report.to_dict()
    assert summary["caller_native_id"].endswith(f"user/{LAB_USER}")
    assert summary["allowed_count"] >= 5
    assert summary["denied_count"] >= 1

    print("\n--- leaked-key probe summary (live LocalStack) ---")
    print(json.dumps({
        "caller": summary["caller_native_id"],
        "allowed": [r["operation"] for r in summary["results"] if r["status"] == "allowed"],
        "denied": [r["operation"] for r in summary["results"] if r["status"] == "denied"],
        "errors": [r["operation"] for r in summary["results"] if r["status"] == "error"],
        "s3_buckets_found": list(bucket_names),
        "secrets_found": list(secret_names),
    }, indent=2))
