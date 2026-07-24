from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.azure.helpers import call_azure
from samoyed.enumerators.azure.targets import resource_group_from_id


class AzureKeyVaultEnumerator:
    concept = ConceptType.SECRET_STORE
    name = "azure-keyvault"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        kv_mgmt = cred.client("keyvault")  # type: ignore[attr-defined]
        vaults = call_azure(
            ctx,
            operation="keyvault.vaults.list",
            call=lambda: list(kv_mgmt.vaults.list()),
        )
        if not vaults:
            return

        for vault in vaults:
            vault_name = vault.name
            vault_uri = vault.properties.vault_uri if vault.properties else None
            yield ConceptArtifact(
                concept_type=ConceptType.SECRET_STORE,
                provider=CloudProvider.AZURE,
                native_id=f"KeyVault:{vault_name}",
                scope_id=ctx.scope.scope_id,
                properties={
                    "resource_type": "KeyVault",
                    "vault_name": vault_name,
                    "vault_uri": vault_uri,
                    "display_name": vault_name,
                    "resource_group": resource_group_from_id(getattr(vault, "id", None)),
                },
                evidence=Evidence("keyvault.vaults.list", {"vault": vault_name}),
            )

            if not vault_uri:
                continue
            try:
                from azure.keyvault.secrets import SecretClient

                secret_client = SecretClient(
                    vault_url=vault_uri, credential=cred.credential()  # type: ignore[attr-defined]
                )
            except ImportError:
                continue

            secrets = call_azure(
                ctx,
                operation=f"keyvault.secrets.list:{vault_name}",
                call=lambda: list(secret_client.list_properties_of_secrets()),
            )
            if not secrets:
                continue
            for secret in secrets:
                sname = secret.name
                native_id = f"KeyVaultSecret:{vault_name}/{sname}"
                yield ConceptArtifact(
                    concept_type=ConceptType.SECRET_STORE,
                    provider=CloudProvider.AZURE,
                    native_id=native_id,
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "resource_type": "KeyVaultSecret",
                        "secret_name": sname,
                        "vault_name": vault_name,
                        "display_name": f"{vault_name}/{sname}",
                    },
                    evidence=Evidence(
                        "keyvault.secrets.list", {"vault": vault_name, "secret": sname}
                    ),
                )
