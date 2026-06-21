from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from samoyed.firing_range.config import (
    ARTIFACTS_DIR,
    CLIENT_IAM_REPORT_FILE,
    CREDENTIALS_FILE,
    DEFAULT_ACCESS_KEY,
    DEFAULT_ENDPOINT,
    DEFAULT_REGION,
    DEFAULT_SECRET_KEY,
    LAB_ADMIN_ROLE,
    LAB_BUCKET,
    LAB_LAMBDA,
    LAB_LAMBDA_ROLE,
    LAB_SECRET,
    LAB_USER,
    LAB_WEB_BUCKET,
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
    write_credentials: bool = True,
) -> dict[str, Any]:
    """
    Seed an AWSGoat-style vulnerable topology into LocalStack via live APIs.

    Paths:
      - leaked-user -> assume admin -> read prod secret / S3
      - leaked-user inline iam:AttachUserPolicy (privesc pattern)
      - lambda-exec role -> read prod-db secret (runtime binding)
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
    # Recon permissions a leaked dev key might still have (client IAM report + probes).
    recon_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:GetUser",
                    "iam:ListUserPolicies",
                    "iam:GetUserPolicy",
                    "iam:ListAttachedUserPolicies",
                    "s3:ListAllMyBuckets",
                    "s3:ListBuckets",
                    "secretsmanager:ListSecrets",
                    "lambda:ListFunctions",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_user_policy(
        UserName=LAB_USER,
        PolicyName="recon-read",
        PolicyDocument=json.dumps(recon_policy),
    )

    s3 = _client("s3", endpoint_url=endpoint_url, region=region)
    _ensure_bucket(s3, LAB_BUCKET, region=region)
    _ensure_bucket(s3, LAB_WEB_BUCKET, region=region)

    secrets = _client("secretsmanager", endpoint_url=endpoint_url, region=region)
    secret_arn = _ensure_secret(secrets, LAB_SECRET)

    lambda_role_arn = _ensure_lambda_execution_role(iam, account, secret_arn)
    lambda_arn = _ensure_lambda(
        _client("lambda", endpoint_url=endpoint_url, region=region),
        role_arn=lambda_role_arn,
        region=region,
    )

    leaked_creds = _ensure_leaked_access_key(iam, endpoint_url=endpoint_url, region=region)
    credentials_path = None
    if write_credentials:
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        credentials_path = str(CREDENTIALS_FILE)
        CREDENTIALS_FILE.write_text(json.dumps(leaked_creds, indent=2), encoding="utf-8")

    return {
        "provider": "aws",
        "emulator": endpoint_url,
        "account_id": account,
        "caller_arn": user_arn,
        "admin_role_arn": admin_arn,
        "bucket": LAB_BUCKET,
        "web_bucket": LAB_WEB_BUCKET,
        "secret_arn": secret_arn,
        "lambda_arn": lambda_arn,
        "lambda_role_arn": lambda_role_arn,
        "leaked_credentials_file": credentials_path,
        "seed_access_key_id": DEFAULT_ACCESS_KEY,
        "hint": (
            f"Leaked key: {credentials_path or 'run with write_credentials=True'} | "
            f"ScoutSuite: samoyed firing-range scoutsuite | "
            f"Client report: samoyed firing-range client-report"
        ),
    }


def ping_emulator(*, endpoint_url: str = DEFAULT_ENDPOINT, region: str = DEFAULT_REGION) -> bool:
    try:
        sts = _client("sts", endpoint_url=endpoint_url, region=region)
        sts.get_caller_identity()
        return True
    except Exception:
        return False


def load_leaked_credentials(path: Path | None = None) -> dict[str, Any]:
    cred_path = path or CREDENTIALS_FILE
    if not cred_path.is_file():
        raise FileNotFoundError(
            f"Leaked credentials not found at {cred_path}. Run: samoyed firing-range seed"
        )
    return json.loads(cred_path.read_text(encoding="utf-8"))


def _ensure_leaked_access_key(iam: Any, *, endpoint_url: str, region: str) -> dict[str, Any]:
    try:
        resp = iam.create_access_key(UserName=LAB_USER)
        key = resp["AccessKey"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "LimitExceeded":
            raise
        keys = iam.list_access_keys(UserName=LAB_USER)["AccessKeyMetadata"]
        if keys:
            iam.delete_access_key(UserName=LAB_USER, AccessKeyId=keys[0]["AccessKeyId"])
        resp = iam.create_access_key(UserName=LAB_USER)
        key = resp["AccessKey"]
    return {
        "AccessKeyId": key["AccessKeyId"],
        "SecretAccessKey": key["SecretAccessKey"],
        "region": region,
        "endpoint_url": endpoint_url,
        "user": LAB_USER,
    }


def _ensure_lambda_execution_role(iam: Any, account: str, secret_arn: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = _ensure_role(iam, LAB_LAMBDA_ROLE, trust)
    read_secret_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                "Resource": secret_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=LAB_LAMBDA_ROLE,
        PolicyName="read-prod-secret",
        PolicyDocument=json.dumps(read_secret_policy),
    )
    return role_arn


def _ensure_lambda(lambda_client: Any, *, role_arn: str, region: str) -> str:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def handler(event, context):\n    return {'statusCode': 200, 'body': 'ok'}\n",
        )
    payload = buf.getvalue()

    try:
        resp = lambda_client.create_function(
            FunctionName=LAB_LAMBDA,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": payload},
            Description="AWSGoat-style vulnerable handler (LocalStack lab)",
        )
        return resp["FunctionArn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise
        return lambda_client.get_function(FunctionName=LAB_LAMBDA)["Configuration"]["FunctionArn"]


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
