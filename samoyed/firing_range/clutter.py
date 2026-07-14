"""
Bronze/silver lab clutter — enumeration noise plus tiered multi-hop attack paths.
"""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from typing import Any, Callable

from botocore.exceptions import ClientError

from samoyed.firing_range.config import (
    BRONZE_BUCKETS,
    BRONZE_IAM_ROLES,
    BRONZE_IAM_USERS,
    BRONZE_LAMBDAS,
    BRONZE_LOAD_BALANCERS,
    BRONZE_SECRETS,
    BRONZE_LAMBDA_EXEC_ROLE,
    SILVER_DEV_BUILD_ROLE,
    SILVER_DEV_BUCKET,
    SILVER_DEV_CICD_ROLE,
    SILVER_DEV_CONFIG_BUCKET,
    SILVER_DEV_EKS,
    SILVER_DEV_LAMBDA,
    SILVER_DEV_PIPELINE,
    SILVER_DEV_SECRET,
    SILVER_PROD_CICD_ROLE,
    SILVER_PROD_EKS,
    SILVER_PROD_PIPELINE,
    SILVER_PROD_SECRET,
)
from samoyed.firing_range import aws_helpers
from samoyed.firing_range.paths import wire_tiered_attack_paths


def seed_lab_clutter(
    *,
    endpoint_url: str,
    region: str,
    account_id: str,
    leaked_user_arn: str,
) -> dict[str, Any]:
    """Best-effort clutter; unsupported LocalStack APIs are skipped, not fatal."""
    report: dict[str, Any] = {"bronze": {}, "silver": {}, "skipped": []}

    s3 = aws_helpers.aws_client("s3", endpoint_url=endpoint_url, region=region)
    iam = aws_helpers.aws_client("iam", endpoint_url=endpoint_url, region=region)
    secrets = aws_helpers.aws_client("secretsmanager", endpoint_url=endpoint_url, region=region)
    lam = aws_helpers.aws_client("lambda", endpoint_url=endpoint_url, region=region)

    bronze_buckets: list[str] = []
    for name in BRONZE_BUCKETS:
        ok, _ = _run(f"bronze:s3:{name}", lambda n=name: aws_helpers.ensure_bucket(s3, n, region=region), report)
        if ok:
            bronze_buckets.append(name)
    report["bronze"]["buckets"] = bronze_buckets

    bronze_secrets: list[str] = []
    for name in BRONZE_SECRETS:
        ok, _ = _run(f"bronze:secret:{name}", lambda n=name: aws_helpers.ensure_secret(secrets, n), report)
        if ok:
            bronze_secrets.append(name)
    report["bronze"]["secrets"] = bronze_secrets

    bronze_users: list[str] = []
    for name in BRONZE_IAM_USERS:
        ok, _ = _run(f"bronze:user:{name}", lambda n=name: aws_helpers.ensure_user(iam, n), report)
        if ok:
            bronze_users.append(name)
    report["bronze"]["users"] = bronze_users

    bronze_roles: list[str] = []
    for name in BRONZE_IAM_ROLES:
        arn = _try_bronze_role(iam, account_id, name, report)
        if arn:
            bronze_roles.append(name)
    report["bronze"]["roles"] = bronze_roles

    bronze_lambdas: list[str] = []
    orphan_role = _try_bronze_role(iam, account_id, BRONZE_LAMBDA_EXEC_ROLE, report)
    if orphan_role:
        for name in BRONZE_LAMBDAS:
            ok, _ = _run(
                f"bronze:lambda:{name}",
                lambda n=name: _ensure_lambda(lam, role_arn=orphan_role, region=region, function_name=n),
                report,
            )
            if ok:
                bronze_lambdas.append(name)
    report["bronze"]["lambdas"] = bronze_lambdas

    bronze_lbs: list[str] = []
    elbv2 = aws_helpers.aws_client("elbv2", endpoint_url=endpoint_url, region=region)
    for name in BRONZE_LOAD_BALANCERS:
        ok, _ = _run(f"bronze:elb:{name}", lambda n=name: _ensure_load_balancer(elbv2, n), report)
        if ok:
            bronze_lbs.append(name)
    report["bronze"]["load_balancers"] = bronze_lbs

    # EC2 instances — classic bronze noise
    ec2 = aws_helpers.aws_client("ec2", endpoint_url=endpoint_url, region=region)
    bronze_instances: list[str] = []
    for name in ("retired-bastion", "pentest-vm-forgotten"):
        iid = _try_ec2_instance(ec2, name, report)
        if iid:
            bronze_instances.append(iid)
    report["bronze"]["ec2_instances"] = bronze_instances

    silver = _seed_silver_platform(
        endpoint_url=endpoint_url,
        region=region,
        account_id=account_id,
        iam=iam,
        s3=s3,
        secrets=secrets,
        lam=lam,
        report=report,
    )
    report["silver"] = silver
    report["attack_paths"] = wire_tiered_attack_paths(
        iam,
        account_id=account_id,
        user_arn=leaked_user_arn,
    )
    return report


def _seed_silver_platform(
    *,
    endpoint_url: str,
    region: str,
    account_id: str,
    iam: Any,
    s3: Any,
    secrets: Any,
    lam: Any,
    report: dict[str, Any],
) -> dict[str, Any]:
    silver: dict[str, Any] = {}

    for bucket in (SILVER_DEV_BUCKET, SILVER_DEV_CONFIG_BUCKET):
        _run(f"silver:s3:{bucket}", lambda b=bucket: aws_helpers.ensure_bucket(s3, b, region=region), report)

    _run(f"silver:secret:{SILVER_DEV_SECRET}", lambda: aws_helpers.ensure_secret(secrets, SILVER_DEV_SECRET), report)
    _run(f"silver:secret:{SILVER_PROD_SECRET}", lambda: aws_helpers.ensure_secret(secrets, SILVER_PROD_SECRET), report)

    dev_cicd_arn = _ensure_cicd_role(
        iam,
        account_id,
        SILVER_DEV_CICD_ROLE,
        environment="dev",
        eks_cluster=SILVER_DEV_EKS,
        artifact_bucket=SILVER_DEV_BUCKET,
    )
    prod_cicd_arn = _ensure_cicd_role(
        iam,
        account_id,
        SILVER_PROD_CICD_ROLE,
        environment="prod",
        eks_cluster=SILVER_PROD_EKS,
        artifact_bucket=SILVER_DEV_BUCKET,
    )
    silver["dev_cicd_role"] = dev_cicd_arn
    silver["prod_cicd_role"] = prod_cicd_arn

    build_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    build_role_arn = aws_helpers.ensure_role(iam, SILVER_DEV_BUILD_ROLE, build_trust)
    iam.put_role_policy(
        RoleName=SILVER_DEV_BUILD_ROLE,
        PolicyName="dev-build-artifacts",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                        "Resource": [
                            f"arn:aws:s3:::{SILVER_DEV_BUCKET}",
                            f"arn:aws:s3:::{SILVER_DEV_BUCKET}/*",
                        ],
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    silver["dev_build_role"] = build_role_arn

    eks = aws_helpers.aws_client("eks", endpoint_url=endpoint_url, region=region)
    for cluster_name, tier in ((SILVER_DEV_EKS, "dev"), (SILVER_PROD_EKS, "prod")):
        arn = _try_eks_cluster(eks, cluster_name, tier, report)
        if arn:
            silver[f"{tier}_eks"] = arn

    codepipeline = aws_helpers.aws_client("codepipeline", endpoint_url=endpoint_url, region=region)
    _try_codepipeline(
        codepipeline,
        name=SILVER_DEV_PIPELINE,
        role_arn=dev_cicd_arn,
        artifact_bucket=SILVER_DEV_BUCKET,
        environment="dev",
        report=report,
    )
    _try_codepipeline(
        codepipeline,
        name=SILVER_PROD_PIPELINE,
        role_arn=prod_cicd_arn,
        artifact_bucket=SILVER_DEV_BUCKET,
        environment="prod",
        report=report,
    )
    silver["pipelines"] = [SILVER_DEV_PIPELINE, SILVER_PROD_PIPELINE]

    if dev_cicd_arn:
        _run(
            f"silver:lambda:{SILVER_DEV_LAMBDA}",
            lambda: _ensure_lambda(
                lam,
                role_arn=dev_cicd_arn,
                region=region,
                function_name=SILVER_DEV_LAMBDA,
                description="Dev-only feature flag sync (silver clutter)",
            ),
            report,
        )
        silver["dev_lambda"] = SILVER_DEV_LAMBDA

    codebuild = aws_helpers.aws_client("codebuild", endpoint_url=endpoint_url, region=region)
    _try_codebuild_project(
        codebuild,
        name="corp-app-dev-build",
        role_arn=build_role_arn,
        artifact_bucket=SILVER_DEV_BUCKET,
        report=report,
    )
    silver["codebuild_projects"] = ["corp-app-dev-build"]

    return silver


def _ensure_cicd_role(
    iam: Any,
    account_id: str,
    role_name: str,
    *,
    environment: str,
    eks_cluster: str,
    artifact_bucket: str,
) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "codepipeline.amazonaws.com",
                        "codebuild.amazonaws.com",
                    ]
                },
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = aws_helpers.ensure_role(iam, role_name, trust)
    if environment == "dev":
        statements = [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket",
                    "codebuild:StartBuild",
                    "codebuild:BatchGetBuilds",
                ],
                "Resource": [
                    f"arn:aws:s3:::{artifact_bucket}",
                    f"arn:aws:s3:::{artifact_bucket}/*",
                    f"arn:aws:codebuild:*:{account_id}:project/corp-app-dev-build",
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["eks:DescribeCluster", "eks:ListClusters"],
                "Resource": f"arn:aws:eks:*:{account_id}:cluster/{eks_cluster}",
            },
            {
                "Effect": "Allow",
                "Action": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
                "Resource": f"arn:aws:lambda:*:{account_id}:function:{SILVER_DEV_LAMBDA}",
            },
        ]
    else:
        # Prod deploy role exists but is not granted to leaked-user; scoped to prod cluster only.
        statements = [
            {
                "Effect": "Allow",
                "Action": ["eks:DescribeCluster", "eks:UpdateClusterConfig"],
                "Resource": f"arn:aws:eks:*:{account_id}:cluster/{eks_cluster}",
            },
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": f"arn:aws:secretsmanager:*:{account_id}:secret:{SILVER_PROD_SECRET}*",
            },
        ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=f"{environment}-cicd-scope",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn


def _try_bronze_role(iam: Any, account_id: str, name: str, report: dict[str, Any]) -> str | None:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    def _create() -> str:
        return aws_helpers.ensure_role(iam, name, trust)

    ok, value = _run(f"bronze:role:{name}", _create, report)
    return value if ok else None


def _ensure_load_balancer(elbv2: Any, name: str) -> None:
    try:
        elbv2.create_load_balancer(Name=name, Scheme="internet-facing", Type="application")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"DuplicateLoadBalancerName", "ResourceInUse"}:
            return
        raise


def _try_ec2_instance(ec2: Any, name: str, report: dict[str, Any]) -> str | None:
    existing = aws_helpers.find_ec2_instance_by_name(ec2, name)
    if existing:
        return existing

    def _create() -> str:
        resp = ec2.run_instances(
            ImageId="ami-00000000",
            MinCount=1,
            MaxCount=1,
            InstanceType="t3.micro",
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": name}, {"Key": "samoyed-tier", "Value": "bronze"}],
                }
            ],
        )
        return resp["Instances"][0]["InstanceId"]

    ok, value = _run(f"bronze:ec2:{name}", _create, report)
    return value if ok else None


def _try_eks_cluster(eks: Any, name: str, tier: str, report: dict[str, Any]) -> str | None:
    def _create() -> str:
        try:
            resp = eks.create_cluster(
                name=name,
                roleArn=f"arn:aws:iam::000000000000:role/eks-cluster-service",
                resourcesVpcConfig={"subnetIds": ["subnet-1"], "securityGroupIds": ["sg-1"]},
                tags={"samoyed-tier": tier, "environment": tier},
            )
            return resp["cluster"]["arn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceInUseException":
                return eks.describe_cluster(name=name)["cluster"]["arn"]
            raise

    ok, value = _run(f"silver:eks:{name}", _create, report)
    return value if ok else None


def _try_codepipeline(
    codepipeline: Any,
    *,
    name: str,
    role_arn: str,
    artifact_bucket: str,
    environment: str,
    report: dict[str, Any],
) -> None:
    def _create() -> None:
        codepipeline.create_pipeline(
            pipeline={
                "name": name,
                "roleArn": role_arn,
                "artifactStore": {"type": "S3", "location": artifact_bucket},
                "stages": [
                    {
                        "name": "Source",
                        "actions": [
                            {
                                "name": "Source",
                                "actionTypeId": {
                                    "category": "Source",
                                    "owner": "AWS",
                                    "provider": "S3",
                                    "version": "1",
                                },
                                "configuration": {"S3Bucket": artifact_bucket, "S3ObjectKey": "source.zip"},
                                "outputArtifacts": [{"name": "SourceOutput"}],
                            }
                        ],
                    },
                    {
                        "name": "Deploy",
                        "actions": [
                            {
                                "name": f"Deploy{environment.title()}",
                                "actionTypeId": {
                                    "category": "Deploy",
                                    "owner": "AWS",
                                    "provider": "CloudFormation",
                                    "version": "1",
                                },
                                "configuration": {"StackName": f"corp-app-{environment}"},
                                "inputArtifacts": [{"name": "SourceOutput"}],
                            }
                        ],
                    },
                ],
                "tags": [{"key": "environment", "value": environment}],
            }
        )

    _run(f"silver:pipeline:{name}", _create, report)


def _try_codebuild_project(
    codebuild: Any,
    *,
    name: str,
    role_arn: str,
    artifact_bucket: str,
    report: dict[str, Any],
) -> None:
    def _create() -> None:
        codebuild.create_project(
            name=name,
            description="Dev build — deploys to dev EKS only (silver clutter)",
            serviceRole=role_arn,
            artifacts={"type": "S3", "location": artifact_bucket, "name": name, "packaging": "ZIP"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            source={"type": "S3", "location": f"{artifact_bucket}/source.zip"},
            tags=[{"key": "environment", "value": "dev"}],
        )

    _run(f"silver:codebuild:{name}", _create, report)


def _run(key: str, fn: Callable[[], Any], report: dict[str, Any]) -> tuple[bool, Any]:
    try:
        return True, fn()
    except ClientError as exc:
        report["skipped"].append({"resource": key, "error": exc.response.get("Error", {})})
        return False, None
    except Exception as exc:  # noqa: BLE001 — LocalStack gaps vary by version
        report["skipped"].append({"resource": key, "error": str(exc)})
        return False, None


def _ensure_lambda(
    lambda_client: Any,
    *,
    role_arn: str,
    region: str,
    function_name: str,
    description: str = "Bronze clutter function",
) -> str:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    payload = buf.getvalue()
    try:
        resp = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": payload},
            Description=description,
        )
        return resp["FunctionArn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise
        return lambda_client.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]
