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
def test_collect_iam_report_expands_assumable_role_policies(mock_identity, mock_client):
    caller = "arn:aws:iam::000000000000:user/leaked-user"
    monitor = "arn:aws:iam::000000000000:role/legacy-monitoring-role"
    bronze_exec = "arn:aws:iam::000000000000:role/bronze-lambda-exec"
    mock_identity.return_value = {"Account": "000000000000", "Arn": caller}

    iam = MagicMock()
    s3 = MagicMock()
    sm = MagicMock()
    lam = MagicMock()
    mock_client.side_effect = lambda service, region=None: {
        "iam": iam,
        "s3": s3,
        "secretsmanager": sm,
        "lambda": lam,
    }[service]

    iam.list_user_policies.return_value = {"PolicyNames": ["tiered-assume"]}
    iam.get_user_policy.return_value = {
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": monitor,
                }
            ]
        }
    }
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    iam.list_users.return_value = {"Users": []}
    iam.list_roles.return_value = {"Roles": []}

    def role_policies(RoleName: str) -> dict:
        if RoleName == "legacy-monitoring-role":
            return {"PolicyNames": ["bronze-monitor-chain"]}
        if RoleName == "bronze-lambda-exec":
            return {"PolicyNames": ["bronze-archive-read"]}
        return {"PolicyNames": []}

    def role_policy(RoleName: str, PolicyName: str) -> dict:
        if RoleName == "legacy-monitoring-role":
            return {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": bronze_exec,
                        }
                    ]
                }
            }
        if RoleName == "bronze-lambda-exec":
            return {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "secretsmanager:GetSecretValue",
                            "Resource": "arn:aws:secretsmanager:us-east-1:000000000000:secret:rotated-api-key-archive*",
                        }
                    ]
                }
            }
        return {"PolicyDocument": {"Statement": []}}

    iam.list_role_policies.side_effect = role_policies
    iam.get_role_policy.side_effect = role_policy
    s3.list_buckets.return_value = {"Buckets": []}
    sm.list_secrets.return_value = {"SecretList": []}
    lam.list_functions.return_value = {"Functions": []}

    report = collect_iam_report(_cred())
    rels = {(g["from"], g["to"], g["rel"]) for g in report["grants"]}
    assert (caller, monitor, "CAN_ASSUME_ROLE") in rels
    assert (monitor, bronze_exec, "CAN_ASSUME_ROLE") in rels
    assert any(
        g["from"] == bronze_exec and g["rel"] == "READS" and "rotated-api-key-archive" in g["to"]
        for g in report["grants"]
    )
