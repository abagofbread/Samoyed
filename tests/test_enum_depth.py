"""Config parsers, Access Analyzer findings, CloudTrail gating, K8s secret consumers."""

from __future__ import annotations

from samoyed.cloud.artifacts import DenialLog
from samoyed.cloud.concepts import CloudProvider
from samoyed.credentials.protocol import EnumContext, ScopeBoundary
from samoyed.enumerators.aws.access_analyzer import _finding_artifacts
from samoyed.enumerators.aws.cloudtrail_observed import cloudtrail_observed_enabled
from samoyed.enumerators.aws.config_refs import config_reads_edges, extract_resource_refs
from samoyed.enumerators.aws.runtime_bindings import lambda_function_artifact
from samoyed.enumerators.k8s.nodes import parse_cloud_instance
from samoyed.enumerators.k8s.secret_consumers import secret_refs_from_pod_spec


def _aws_ctx() -> EnumContext:
    return EnumContext(
        credentials=object(),  # type: ignore[arg-type]
        session_id="test",
        scope=ScopeBoundary(
            provider=CloudProvider.AWS,
            scope_id="aws:123",
            display_name="test",
            properties={},
        ),
        denial_log=DenialLog(),
    )


def test_extract_secret_s3_kms_from_env_text():
    text = (
        "arn:aws:secretsmanager:us-east-1:123:secret:prod/db-AbCdEf "
        "s3://data-lake/prefix "
        "arn:aws:kms:us-east-1:123:key/11111111-2222-3333-4444-555555555555"
    )
    refs = extract_resource_refs(text)
    kinds = {r[1] for r in refs}
    assert "Secret" in kinds
    assert "S3Bucket" in kinds
    assert "KMSKey" in kinds


def test_lambda_config_emits_reads_edges():
    art = lambda_function_artifact(
        _aws_ctx(),
        fn_arn="arn:aws:lambda:us-east-1:123:function:app",
        function_name="app",
        role_arn="arn:aws:iam::123:role/app",
        env={
            "DB_SECRET": "arn:aws:secretsmanager:us-east-1:123:secret:prod/db-AbCdEf",
            "BUCKET": "s3://app-data/",
        },
        evidence_op="test",
        evidence_details={},
    )
    targets = {e.target_native_id for e in art.edges if e.rel_type == "READS"}
    assert any(t.startswith("Secret:") for t in targets)
    assert "S3Bucket:app-data" in targets


def test_config_reads_ecr_image():
    edges = config_reads_edges(
        source="lambda-config",
        image_uri="123.dkr.ecr.us-east-1.amazonaws.com/app:latest",
    )
    rels = {e.rel_type for e in edges}
    assert "USES_IMAGE" in rels
    assert "PULLS_FROM" in rels


def test_access_analyzer_finding_to_edge():
    finding = {
        "id": "finding-1",
        "resource": "arn:aws:s3:::corp-secrets",
        "resourceType": "AWS::S3::Bucket",
        "principal": {"AWS": "arn:aws:iam::999:root"},
        "action": ["s3:GetObject"],
        "isPublic": False,
        "status": "ACTIVE",
    }
    arts = list(_finding_artifacts(_aws_ctx(), finding, analyzer_name="account"))
    assert arts
    edge_art = next(a for a in arts if a.edges)
    assert edge_art.edges[0].rel_type == "READS"
    assert edge_art.edges[0].props["discovered_via"] == "access-analyzer"
    assert edge_art.edges[0].props["is_external"] is True


def test_cloudtrail_gated_off_by_default():
    assert cloudtrail_observed_enabled(None) is False


def test_k8s_secret_consumers_from_env_and_volume():
    spec = {
        "metadata": {"namespace": "prod", "name": "api"},
        "spec": {
            "containers": [
                {
                    "name": "api",
                    "env": [
                        {
                            "name": "DB",
                            "valueFrom": {"secretKeyRef": {"name": "db-creds", "key": "pass"}},
                        }
                    ],
                    "envFrom": [{"secretRef": {"name": "app-config"}}],
                }
            ],
            "volumes": [{"name": "tls", "secret": {"secretName": "tls-cert"}}],
        },
    }
    refs = secret_refs_from_pod_spec(spec)
    names = {r["name"] for r in refs}
    assert names == {"db-creds", "app-config", "tls-cert"}


def test_parse_eks_provider_id():
    cloud = parse_cloud_instance("aws:///us-east-1a/i-0abc123def456")
    assert cloud["aws_instance_id"] == "i-0abc123def456"
    assert cloud["ec2_native_id"] == "EC2Instance:i-0abc123def456"
