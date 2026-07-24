from __future__ import annotations

from samoyed.cloud.capabilities import gcp_role_to_actions, map_azure_role, map_gcp_role


def test_map_gcp_role_secret_accessor():
    m = map_gcp_role("roles/secretmanager.secretAccessor")
    assert m is not None
    assert m.capability.value == "READS"


def test_map_azure_role_keyvault():
    m = map_azure_role("Key Vault Secrets User")
    assert m is not None
    assert m.capability.value == "READS"


def test_gcp_p0_role_actions_cover_attack_patterns():
    assert "gcp:iam.serviceAccounts.getAccessToken" in gcp_role_to_actions(
        "roles/iam.serviceAccountTokenCreator"
    )
    assert "gcp:cloudbuild.builds.create" in gcp_role_to_actions("roles/cloudbuild.builds.builder")
    assert "gcp:compute.instances.setMetadata" in gcp_role_to_actions(
        "roles/compute.instanceAdmin.v1"
    )
