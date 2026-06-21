from __future__ import annotations

from samoyed.cloud.capabilities import map_azure_role, map_gcp_role


def test_map_gcp_role_secret_accessor():
    m = map_gcp_role("roles/secretmanager.secretAccessor")
    assert m is not None
    assert m.capability.value == "READS"


def test_map_azure_role_keyvault():
    m = map_azure_role("Key Vault Secrets User")
    assert m is not None
    assert m.capability.value == "READS"
