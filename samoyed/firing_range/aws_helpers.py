from __future__ import annotations

import json
from typing import Any

import boto3
from botocore.exceptions import ClientError

from samoyed.firing_range.config import DEFAULT_ACCESS_KEY, DEFAULT_SECRET_KEY


def aws_client(service: str, *, endpoint_url: str, region: str) -> Any:
    return boto3.client(
        service,
        endpoint_url=endpoint_url,
        region_name=region,
        aws_access_key_id=DEFAULT_ACCESS_KEY,
        aws_secret_access_key=DEFAULT_SECRET_KEY,
    )


def ensure_user(iam: Any, name: str) -> None:
    try:
        iam.create_user(UserName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise


def ensure_role(iam: Any, name: str, trust: dict[str, Any]) -> str:
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


def ensure_bucket(s3: Any, name: str, *, region: str) -> None:
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


def ensure_secret(secrets: Any, name: str) -> str:
    try:
        resp = secrets.create_secret(Name=name, SecretString="emulated-db-password")
        return resp["ARN"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceExistsException":
            raise
        return secrets.describe_secret(SecretId=name)["ARN"]
