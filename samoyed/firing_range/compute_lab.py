from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from samoyed.firing_range import aws_helpers
from samoyed.firing_range.config import (
    LAB_GPU_SPOT_NAME,
    LAB_INTERNAL_WRITER_ROLE,
    LAB_MARKETING_WEB_NAME,
    LAB_MARKETING_WEB_PROFILE,
    LAB_MARKETING_WEB_ROLE,
    LAB_ML_ARTIFACTS_BUCKET,
    LAB_ML_GPU_NAME,
    LAB_ML_GPU_PROFILE,
    LAB_ML_GPU_ROLE,
    LAB_WEB_BUCKET,
)


def seed_compute_lab(
    *,
    iam: Any,
    ec2: Any,
    s3: Any,
    account: str,
    region: str,
    internal_writer_role_arn: str | None = None,
) -> dict[str, Any]:
    """
    EC2 compute shapes for the firing range:
      - marketing-web: SSRF-vulnerable web tier + instance profile (IMDS → role chain)
      - ml-training-gpu: GPU instance for ML / mining-abuse modeling
      - legacy-crypto-gpu-spot: bronze GPU noise
    """
    aws_helpers.ensure_bucket(s3, LAB_ML_ARTIFACTS_BUCKET, region=region)

    writer_arn = internal_writer_role_arn or aws_helpers.ensure_role(
        iam,
        LAB_INTERNAL_WRITER_ROLE,
        _ec2_trust(),
    )

    marketing_role_arn = _ensure_marketing_web_role(iam, writer_arn)
    gpu_role_arn = _ensure_ml_gpu_role(iam, account)

    aws_helpers.ensure_instance_profile(iam, LAB_MARKETING_WEB_PROFILE, LAB_MARKETING_WEB_ROLE)
    aws_helpers.ensure_instance_profile(iam, LAB_ML_GPU_PROFILE, LAB_ML_GPU_ROLE)

    marketing_id = _ensure_ec2(
        ec2,
        name=LAB_MARKETING_WEB_NAME,
        instance_type="t3.small",
        profile_name=LAB_MARKETING_WEB_PROFILE,
        tags={
            "Name": LAB_MARKETING_WEB_NAME,
            "samoyed-tier": "gold",
            "samoyed:ssrf_vulnerable": "true",
            "samoyed:internet_exposed": "true",
            "samoyed:workload": "marketing-web",
        },
    )
    gpu_id = _ensure_ec2(
        ec2,
        name=LAB_ML_GPU_NAME,
        instance_type="g4dn.xlarge",
        profile_name=LAB_ML_GPU_PROFILE,
        tags={
            "Name": LAB_ML_GPU_NAME,
            "samoyed-tier": "gold",
            "samoyed:compute_class": "gpu",
            "samoyed:gpu_accelerated": "true",
            "samoyed:workload": "ml-training",
        },
    )
    spot_id = _ensure_ec2(
        ec2,
        name=LAB_GPU_SPOT_NAME,
        instance_type="p3.2xlarge",
        profile_name=None,
        tags={
            "Name": LAB_GPU_SPOT_NAME,
            "samoyed-tier": "bronze",
            "samoyed:compute_class": "gpu",
            "samoyed:workload": "orphan-spot",
        },
    )

    return {
        "marketing_web": {
            "instance_id": marketing_id,
            "role_arn": marketing_role_arn,
            "profile": LAB_MARKETING_WEB_PROFILE,
            "ssrf_vulnerable": True,
            "imds_story": "EC2 → IMDS → marketing-web-instance → internal-data-writer → pci-internal-ledger",
        },
        "ml_training_gpu": {
            "instance_id": gpu_id,
            "role_arn": gpu_role_arn,
            "profile": LAB_ML_GPU_PROFILE,
            "instance_type": "g4dn.xlarge",
            "compute_class": "gpu",
        },
        "legacy_gpu_spot": {
            "instance_id": spot_id,
            "instance_type": "p3.2xlarge",
            "compute_class": "gpu",
            "note": "orphan GPU — no instance profile",
        },
        "ml_artifacts_bucket": LAB_ML_ARTIFACTS_BUCKET,
    }


def _ec2_trust() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _ensure_marketing_web_role(iam: Any, writer_arn: str) -> str:
    role_arn = aws_helpers.ensure_role(iam, LAB_MARKETING_WEB_ROLE, _ec2_trust())
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:aws:s3:::{LAB_WEB_BUCKET}",
                    f"arn:aws:s3:::{LAB_WEB_BUCKET}/*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": writer_arn,
            },
        ],
    }
    iam.put_role_policy(
        RoleName=LAB_MARKETING_WEB_ROLE,
        PolicyName="marketing-web-access",
        PolicyDocument=json.dumps(policy),
    )
    return role_arn


def _ensure_ml_gpu_role(iam: Any, account: str) -> str:
    role_arn = aws_helpers.ensure_role(iam, LAB_ML_GPU_ROLE, _ec2_trust())
    self_role = f"arn:aws:iam::{account}:role/{LAB_ML_GPU_ROLE}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:aws:s3:::{LAB_ML_ARTIFACTS_BUCKET}",
                    f"arn:aws:s3:::{LAB_ML_ARTIFACTS_BUCKET}/*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:RunInstances",
                    "ec2:RequestSpotInstances",
                    "ec2:DescribeInstances",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": self_role,
            },
        ],
    }
    iam.put_role_policy(
        RoleName=LAB_ML_GPU_ROLE,
        PolicyName="ml-gpu-runner",
        PolicyDocument=json.dumps(policy),
    )
    return role_arn


def _ensure_ec2(
    ec2: Any,
    *,
    name: str,
    instance_type: str,
    profile_name: str | None,
    tags: dict[str, str],
) -> str | None:
    existing = _find_instance_by_name(ec2, name)
    if existing:
        return existing

    params: dict[str, Any] = {
        "ImageId": "ami-00000000",
        "MinCount": 1,
        "MaxCount": 1,
        "InstanceType": instance_type,
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
            }
        ],
    }
    if profile_name:
        params["IamInstanceProfile"] = {"Name": profile_name}

    try:
        resp = ec2.run_instances(**params)
        return resp["Instances"][0]["InstanceId"]
    except ClientError:
        return None


def _find_instance_by_name(ec2: Any, name: str) -> str | None:
    return aws_helpers.find_ec2_instance_by_name(ec2, name)
