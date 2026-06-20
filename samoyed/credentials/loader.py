from __future__ import annotations

from pathlib import Path

from samoyed.credentials.aws import AwsCredential
from samoyed.credentials.azure import AzureCredential
from samoyed.credentials.gcp import GcpCredential
from samoyed.credentials.k8s import K8sCredential


def load_aws_credential(
    *,
    profile: str | None = None,
    key_file: Path | None = None,
    region: str | None = None,
    endpoint_url: str | None = None,
) -> AwsCredential:
    if key_file:
        return AwsCredential.from_key_file(key_file, region=region)
    if profile:
        return AwsCredential.from_profile(profile, region=region, endpoint_url=endpoint_url)
    return AwsCredential.from_env(region=region, endpoint_url=endpoint_url)


def load_k8s_credential(
    *,
    kubeconfig: Path | str | None = None,
    context: str | None = None,
    in_cluster: bool = False,
) -> K8sCredential:
    if in_cluster:
        return K8sCredential.in_cluster()
    return K8sCredential.from_kubeconfig(kubeconfig, context=context)


def load_gcp_credential(
    *,
    key_file: Path | str | None = None,
    project_id: str | None = None,
) -> GcpCredential:
    if key_file:
        return GcpCredential.from_key_file(key_file, project_id=project_id)
    return GcpCredential.from_env(project_id=project_id)


def load_azure_credential(
    *,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    subscription_id: str | None = None,
) -> AzureCredential:
    return AzureCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        subscription_id=subscription_id,
    )
