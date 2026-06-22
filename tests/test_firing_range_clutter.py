"""Unit tests for bronze/silver firing-range clutter seeding."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from samoyed.firing_range.clutter import seed_lab_clutter
from samoyed.firing_range.config import BRONZE_BUCKETS, SILVER_DEV_EKS, SILVER_DEV_PIPELINE


@patch("samoyed.firing_range.aws_helpers.aws_client")
def test_seed_lab_clutter_reports_bronze_and_silver(mock_client_factory):
    iam = MagicMock()
    s3 = MagicMock()
    secrets = MagicMock()
    lam = MagicMock()
    elbv2 = MagicMock()
    ec2 = MagicMock()
    eks = MagicMock()
    codepipeline = MagicMock()
    codebuild = MagicMock()
    fallback = MagicMock()

    def factory(service: str, **kwargs):
        return {
            "iam": iam,
            "s3": s3,
            "secretsmanager": secrets,
            "lambda": lam,
            "elbv2": elbv2,
            "ec2": ec2,
            "eks": eks,
            "codepipeline": codepipeline,
            "codebuild": codebuild,
        }.get(service, fallback)

    mock_client_factory.side_effect = factory

    iam.create_role.return_value = {"Role": {"Arn": "arn:aws:iam::000000000000:role/x"}}
    iam.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::000000000000:role/x"}}
    secrets.create_secret.return_value = {"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:x"}
    lam.create_function.return_value = {"FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:x"}
    ec2.run_instances.return_value = {"Instances": [{"InstanceId": "i-bronze123"}]}
    eks.create_cluster.return_value = {"cluster": {"arn": f"arn:aws:eks:us-east-1:000000000000:cluster/{SILVER_DEV_EKS}"}}

    report = seed_lab_clutter(
        endpoint_url="http://localhost:4566",
        region="us-east-1",
        account_id="000000000000",
        leaked_user_arn="arn:aws:iam::000000000000:user/leaked-user",
    )

    assert len(report["bronze"]["buckets"]) == len(BRONZE_BUCKETS)
    assert report["silver"]["pipelines"] == [SILVER_DEV_PIPELINE, "corp-app-prod-pipeline"]
    assert "attack_paths" in report
    assert report["attack_paths"]["bronze"]["three_hop"]
    assert s3.create_bucket.call_count >= len(BRONZE_BUCKETS)
    codepipeline.create_pipeline.assert_called()
