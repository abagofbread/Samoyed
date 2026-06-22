"""
Bronze/silver multi-hop attack paths from leaked-user.

Bronze (2–3 hops): stale monitoring chain → bronze secrets / junk bucket.
Silver (3 hops): dev staging operator → dev CI/CD → dev secrets/artifacts (not prod).
"""

from __future__ import annotations

import json
from typing import Any

from samoyed.firing_range import aws_helpers
from samoyed.firing_range.config import (
    BRONZE_CHAIN_SECRET,
    BRONZE_LAMBDA_EXEC_ROLE,
    BRONZE_PATH_BUCKET,
    BRONZE_PATH_SECRET,
    LAB_USER,
    SILVER_DEV_BUCKET,
    SILVER_DEV_CICD_ROLE,
    SILVER_DEV_CONFIG_BUCKET,
    SILVER_DEV_SECRET,
    SILVER_DEV_STAGING_ROLE,
)


def _role_arn(account_id: str, name: str) -> str:
    return f"arn:aws:iam::{account_id}:role/{name}"


def _user_arn(account_id: str, username: str = LAB_USER) -> str:
    return f"arn:aws:iam::{account_id}:user/{username}"


def _secret_resource(account_id: str, name: str) -> str:
    return f"arn:aws:secretsmanager:*:{account_id}:secret:{name}*"


def wire_tiered_attack_paths(
    iam: Any,
    *,
    account_id: str,
    user_arn: str,
) -> dict[str, Any]:
    """Attach trusts and policies so bronze/silver chains are queryable from leaked-user."""
    staging_arn = _ensure_staging_operator(iam, account_id, user_arn)
    monitor_arn = _role_arn(account_id, "legacy-monitoring-role")
    auditor_arn = _role_arn(account_id, "stray-config-auditor")
    bronze_exec_arn = _role_arn(account_id, BRONZE_LAMBDA_EXEC_ROLE)
    dev_cicd_arn = _role_arn(account_id, SILVER_DEV_CICD_ROLE)

    _set_role_trust(
        iam,
        "legacy-monitoring-role",
        aws_principals=[user_arn],
        services=["ec2.amazonaws.com"],
    )
    _set_role_trust(
        iam,
        "stray-config-auditor",
        aws_principals=[user_arn],
        services=["ec2.amazonaws.com"],
    )
    _set_role_trust(
        iam,
        BRONZE_LAMBDA_EXEC_ROLE,
        aws_principals=[monitor_arn],
        services=["lambda.amazonaws.com"],
    )
    _set_role_trust(
        iam,
        SILVER_DEV_CICD_ROLE,
        aws_principals=[staging_arn],
        services=["codepipeline.amazonaws.com", "codebuild.amazonaws.com"],
    )

    iam.put_role_policy(
        RoleName="legacy-monitoring-role",
        PolicyName="bronze-monitor-chain",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                        "Resource": _secret_resource(account_id, BRONZE_PATH_SECRET),
                    },
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": bronze_exec_arn,
                    },
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName=BRONZE_LAMBDA_EXEC_ROLE,
        PolicyName="bronze-archive-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                        "Resource": _secret_resource(account_id, BRONZE_CHAIN_SECRET),
                    }
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName="stray-config-auditor",
        PolicyName="bronze-bucket-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [
                            f"arn:aws:s3:::{BRONZE_PATH_BUCKET}",
                            f"arn:aws:s3:::{BRONZE_PATH_BUCKET}/*",
                        ],
                    }
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName=SILVER_DEV_STAGING_ROLE,
        PolicyName="silver-staging-assume",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": dev_cicd_arn,
                    }
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName=SILVER_DEV_CICD_ROLE,
        PolicyName="dev-deploy-data-stores",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                        "Resource": _secret_resource(account_id, SILVER_DEV_SECRET),
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [
                            f"arn:aws:s3:::{SILVER_DEV_BUCKET}",
                            f"arn:aws:s3:::{SILVER_DEV_BUCKET}/*",
                            f"arn:aws:s3:::{SILVER_DEV_CONFIG_BUCKET}",
                            f"arn:aws:s3:::{SILVER_DEV_CONFIG_BUCKET}/*",
                        ],
                    },
                ],
            }
        ),
    )

    username = user_arn.split("/")[-1]
    iam.put_user_policy(
        UserName=username,
        PolicyName="tiered-assume-bronze-silver",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": [
                            monitor_arn,
                            auditor_arn,
                            staging_arn,
                        ],
                    }
                ],
            }
        ),
    )

    return {
        "bronze": {
            "two_hop": [
                {"via": "legacy-monitoring-role", "target": BRONZE_PATH_SECRET, "kind": "secret"},
                {"via": "stray-config-auditor", "target": BRONZE_PATH_BUCKET, "kind": "s3"},
            ],
            "three_hop": [
                {
                    "chain": ["legacy-monitoring-role", BRONZE_LAMBDA_EXEC_ROLE],
                    "target": BRONZE_CHAIN_SECRET,
                    "kind": "secret",
                }
            ],
        },
        "silver": {
            "three_hop": [
                {
                    "chain": [SILVER_DEV_STAGING_ROLE, SILVER_DEV_CICD_ROLE],
                    "targets": [SILVER_DEV_SECRET, SILVER_DEV_BUCKET, SILVER_DEV_CONFIG_BUCKET],
                }
            ],
        },
    }


def _ensure_staging_operator(iam: Any, account_id: str, user_arn: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": user_arn},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    return aws_helpers.ensure_role(iam, SILVER_DEV_STAGING_ROLE, trust)


def _set_role_trust(
    iam: Any,
    role_name: str,
    *,
    aws_principals: list[str] | None = None,
    services: list[str] | None = None,
) -> None:
    principal: dict[str, Any] = {}
    if aws_principals:
        principal["AWS"] = aws_principals[0] if len(aws_principals) == 1 else aws_principals
    if services:
        principal["Service"] = services[0] if len(services) == 1 else services
    iam.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": principal,
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
