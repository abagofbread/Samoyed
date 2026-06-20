from __future__ import annotations

import os
from typing import Any

from samoyed.cloud.concepts import CloudProvider
from samoyed.cloud.providers import make_scope_id
from samoyed.credentials.protocol import ScopeBoundary


def _require_azure():
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
    except ImportError as exc:
        raise ImportError("Install Azure support: pip install 'samoyed[azure]'") from exc
    return ClientSecretCredential, DefaultAzureCredential


class AzureCredential:
    provider = CloudProvider.AZURE

    def __init__(
        self,
        *,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        subscription_id: str | None = None,
    ) -> None:
        ClientSecretCredential, DefaultAzureCredential = _require_azure()

        self.tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID", "")
        self.client_id = client_id or os.environ.get("AZURE_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("AZURE_CLIENT_SECRET")
        self.subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")

        if self.client_id and self.client_secret and self.tenant_id:
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
            self._principal_kind = "ServicePrincipal"
        else:
            self._credential = DefaultAzureCredential()
            self._principal_kind = "User"
            if not self.subscription_id:
                self.subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")

        if not self.subscription_id:
            raise ValueError("AZURE_SUBSCRIPTION_ID is required")

        self._caller: dict[str, Any] | None = None

    @classmethod
    def from_env(cls) -> AzureCredential:
        return cls()

    def credential(self) -> Any:
        return self._credential

    def client(self, service: str, region: str | None = None) -> Any:
        del region
        cred = self._credential
        sub = self.subscription_id

        if service in {"authorization", "rbac"}:
            from azure.mgmt.authorization import AuthorizationManagementClient

            return AuthorizationManagementClient(cred, sub)
        if service in {"storage"}:
            from azure.mgmt.storage import StorageManagementClient

            return StorageManagementClient(cred, sub)
        if service in {"keyvault", "vaults"}:
            from azure.mgmt.keyvault import KeyVaultManagementClient

            return KeyVaultManagementClient(cred, sub)
        if service in {"secrets"}:
            raise ValueError("Use keyvault client for vault URI, then SecretClient per vault")
        if service in {"resource", "subscription"}:
            from azure.mgmt.resource import SubscriptionClient

            return SubscriptionClient(cred)
        raise ValueError(f"Unknown Azure service: {service}")

    def get_caller_identity(self) -> dict[str, Any]:
        if self._caller is None:
            if self._principal_kind == "ServicePrincipal":
                native_id = sp_native_id(self.client_id)
                display = self.client_id
            else:
                native_id = "azure:user:current"
                display = "current-user"
            self._caller = {
                "native_id": native_id,
                "native_kind": self._principal_kind,
                "client_id": self.client_id or None,
                "tenant_id": self.tenant_id or None,
                "subscription_id": self.subscription_id,
                "display": display,
            }
        return self._caller

    def resolve_scope(self) -> ScopeBoundary:
        ident = self.get_caller_identity()
        scope_id = make_scope_id(CloudProvider.AZURE, "subscription", self.subscription_id)
        return ScopeBoundary(
            provider=CloudProvider.AZURE,
            scope_id=scope_id,
            display_name=f"Azure subscription {self.subscription_id[:8]}…",
            properties={
                "subscription_id": self.subscription_id,
                "tenant_id": self.tenant_id,
                "native_id": ident["native_id"],
            },
        )

    def fingerprint(self) -> str:
        return self.get_caller_identity()["native_id"]


def sp_native_id(client_id: str) -> str:
    return f"azure:serviceprincipal:{client_id}"
