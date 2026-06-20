from __future__ import annotations

from unittest.mock import MagicMock, patch

from samoyed.probes.aws import run_aws_probe
from samoyed.probes.models import ApiProbe
from samoyed.probes.runner import probe_to_artifacts, run_api_probes
from samoyed.cloud.concepts import CapabilityType, CloudProvider
from botocore.exceptions import ClientError


def test_run_aws_probe_s3_allowed():
    cred = MagicMock()
    cred.client.return_value.list_buckets.return_value = {"Buckets": [{"Name": "keys-store"}]}
    probe = ApiProbe("s3:ListBuckets", "list", CapabilityType.READS, "S3Bucket")
    result = run_aws_probe(cred, probe)
    assert result.status == "allowed"
    assert result.resources[0]["name"] == "keys-store"


def test_run_aws_probe_iam_denied():
    cred = MagicMock()
    cred.client.return_value.list_users.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListUsers"
    )
    probe = ApiProbe("iam:ListUsers", "list", CapabilityType.READS, "Identity")
    result = run_aws_probe(cred, probe)
    assert result.status == "denied"


@patch("samoyed.probes.runner.run_aws_probe")
def test_run_api_probes_builds_report(mock_run):
    from samoyed.credentials.protocol import ScopeBoundary
    from samoyed.probes.aws import AWS_PROBE_CATALOG

    cred = MagicMock()
    cred.provider = CloudProvider.AWS
    cred.resolve_scope.side_effect = Exception("no iam")
    cred.get_caller_identity.side_effect = Exception("no sts")
    cred._session = MagicMock()
    cred._session.get_credentials.return_value = MagicMock(access_key="AKIATEST")

    def fake_run(c, probe):
        from samoyed.probes.models import ProbeResult

        if probe.operation == "sts:GetCallerIdentity":
            return ProbeResult(
                probe.operation,
                "allowed",
                metadata={"identity": {"Arn": "arn:aws:iam::123:user/leaked", "Account": "123"}},
            )
        if probe.operation == "s3:ListBuckets":
            return ProbeResult(probe.operation, "allowed", resources=[{"name": "auth-keys"}])
        return ProbeResult(probe.operation, "denied", error_code="AccessDenied")

    mock_run.side_effect = fake_run

    probes = [p for p in AWS_PROBE_CATALOG if p.operation in ("sts:GetCallerIdentity", "s3:ListBuckets", "iam:ListUsers")]
    with patch("samoyed.probes.runner.get_probe_catalog", return_value=probes):
        report = run_api_probes(cred)

    assert report.caller_native_id == "arn:aws:iam::123:user/leaked"
    assert any(r.operation == "s3:ListBuckets" and r.status == "allowed" for r in report.results)

    scope = ScopeBoundary(
        provider=CloudProvider.AWS,
        scope_id="aws:account:123",
        display_name="test",
        properties={"native_id": report.caller_native_id},
    )
    artifacts = probe_to_artifacts(report, scope)
    assert len(artifacts) >= 2
    assert any(a.properties.get("bucket_name") == "auth-keys" for a in artifacts)
