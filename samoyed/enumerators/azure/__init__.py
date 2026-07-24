from __future__ import annotations

from samoyed.enumerators.azure.compute import AzureComputeEnumerator
from samoyed.enumerators.azure.entitlement import AzureEntitlementEnumerator
from samoyed.enumerators.azure.federation import AzureFederationEnumerator
from samoyed.enumerators.azure.identity import AzureIdentityEnumerator
from samoyed.enumerators.azure.keyvault import AzureKeyVaultEnumerator
from samoyed.enumerators.azure.storage import AzureStorageEnumerator

AZURE_ENUMERATORS = [
    AzureIdentityEnumerator(),
    AzureEntitlementEnumerator(),
    AzureComputeEnumerator(),
    AzureStorageEnumerator(),
    AzureKeyVaultEnumerator(),
    AzureFederationEnumerator(),
]

__all__ = [
    "AZURE_ENUMERATORS",
    "AzureIdentityEnumerator",
    "AzureEntitlementEnumerator",
    "AzureComputeEnumerator",
    "AzureStorageEnumerator",
    "AzureKeyVaultEnumerator",
    "AzureFederationEnumerator",
]
