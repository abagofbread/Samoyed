from __future__ import annotations

import json
from typing import Any

import boto3
from botocore.exceptions import ClientError

from samoyed.firing_range.config import (
    DEFAULT_ACCESS_KEY,
    DEFAULT_ENDPOINT,
    DEFAULT_REGION,
    DEFAULT_SECRET_KEY,
    LAB_ADMIN_ROLE,
    LAB_BUCKET,
    LAB_SECRET,
    LAB_USER,
)


def _client(service: str, *, endpoint_url: str, region: str) -> Any:
    return boto3.client(
        service,
        endpoint_url=endpoint_url,
        region_name=region,
        aws_access_key_id=DEFAULT_ACCESS_KEY,
        aws_secret_access_key=DEFAULT_SECRET_KEY,
    )


def _account_id(sts: Any) -> str:
    return sts.get_caller_identity()["Account"]


def seed_aws_lab(
    *,
    endpoint_url: str = DEFAULT_ENDPOINT,
    region: str = DEFAULT_REGION,
) -> dict[str, Any]:
    """
    Seed a small vulnerable AWS topology into LocalStack (or any Moto-compatible endpoint).

    Path intent: leaked-user -> assume admin -> read prod secret / S3 bucket.
    """
    iam = _client("iam", endpoint_url=endpoint_url, region=region)
    sts = _client("sts", endpoint_url=endpoint_url, region=region)
    account = _account_id(sts)

    _ensure_user(iam, LAB_USER)
    user_arn = f"arn:aws:iam::{account}:user/{LAB_USER}"

    admin_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": user_arn},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    admin_arn = _ensure_role(iam, LAB_ADMIN_ROLE, admin_trust)
    _attach_admin_access(iam, LAB_ADMIN_ROLE)

    assume_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": admin_arn,
            }
        ],
    }
    iam.put_user_policy(
        UserName=LAB_USER,
        PolicyName="assume-admin",
        PolicyDocument=json.dumps(assume_policy),
    )
    # Direct IAM privesc pattern (matches offline sample-lab graph).
    privesc_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:AttachUserPolicy", "iam:PutUserPolicy"],
                "Resource": user_arn,
            }
        ],
    }
    iam.put_user_policy(
        UserName=LAB_USER,
        PolicyName="self-attach",
        PolicyDocument=json.dumps(privesc_policy),
    )

    s3 = _client("s3", endpoint_url=endpoint_url, region=region)
    _ensure_bucket(s3, LAB_BUCKET, region=region)

    secrets = _client("secretsmanager", endpoint_url=endpoint_url, region=region)
    secret_arn = _ensure_secret(secrets, LAB_SECRET)

    return {
        "provider": "aws",
        "emulator": endpoint_url,
        "account_id": account,
        "caller_arn": user_arn,
        "admin_role_arn": admin_arn,
        "bucket": LAB_BUCKET,
        "secret_arn": secret_arn,
        "access_key_id": DEFAULT_ACCESS_KEY,
        "hint": f"AWS_ACCESS_KEY_ID={DEFAULT_ACCESS_KEY} AWS_SECRET_ACCESS_KEY={DEFAULT_SECRET_KEY} "
        f"AWS_ENDPOINT_URL={endpoint_url} samoyed enum --key-file <(echo '{{...}}')",
    }


def ping_emulator(*, endpoint_url: str = DEFAULT_ENDPOINT, region: str = DEFAULT_REGION) -> bool:
    try:
        sts = _client("sts", endpoint_url=endpoint_url, region=region)
        sts.get_caller_identity()
        return True
    except Exception:
        return False


def _ensure_user(iam: Any, name: str) -> None:
    try:
        iam.create_user(UserName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise


def _ensure_role(iam: Any, name: str, trust: dict[str, Any]) -> str:
    try:
        resp = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust),
        )
        return resp["Role"]["Arn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise
        return iam.get_role(RoleName=name)["Role"]["Arn"]


def _attach_admin_access(iam: Any, role_name: str) -> None:
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise


def _ensure_bucket(s3: Any, name: str, *, region: str) -> None:
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=name)
        else:
            s3.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            raise


def _ensure_secret(secrets: Any, name: str) -> str:
    try:
        resp = secrets.create_secret(Name=name, SecretString="emulated-db-password")
        return resp["ARN"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceExistsException":
            raise
        return secrets.describe_secret(SecretId=name)["ARN"]
