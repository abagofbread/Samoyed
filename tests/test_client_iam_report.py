from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from samoyed.client.iam_report import collect_iam_report
from samoyed.credentials.aws import AwsCredential


def _cred() -> AwsCredential:
    return AwsCredential(
        access_key="AKIA_TEST",
        secret_key="secret",
        region="us-east-1",
        endpoint_url="http://localhost:4566",
    )


@patch("samoyed.client.iam_report.AwsCredential.client")
@patch("samoyed.client.iam_report.AwsCredential.get_caller_identity")
def test_collect_iam_report_parses_inline_policies(mock_identity, mock_client):
    mock_identity.return_value = {
        "Account": "000000000000",
        "Arn": "arn:aws:iam::000000000000:user/leaked-user",
    }
    iam = MagicMock()
    s3 = MagicMock()
    sm = MagicMock()
    lam = MagicMock()

    def client(service: str, region: str | None = None):
        return {"iam": iam, "s3": s3, "secretsmanager": sm, "lambda": lam}[service]

    mock_client.side_effect = client

    iam.list_user_policies.return_value = {"PolicyNames": ["assume-admin"]}
    iam.get_user_policy.return_value = {
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::000000000000:role/admin",
                }
            ]
        }
    }
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    s3.list_buckets.return_value = {"Buckets": [{"Name": "prod-data"}]}
    sm.list_secrets.return_value = {
        "SecretList": [{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:prod-db", "Name": "prod-db"}]
    }
    lam.list_functions.return_value = {"Functions": []}

    report = collect_iam_report(_cred())
    assert report["account_id"] == "000000000000"
    assert any(g["rel"] == "CAN_ASSUME_ROLE" for g in report["grants"])
    assert any(r["id"] == "S3Bucket:prod-data" for r in report["resources"])
