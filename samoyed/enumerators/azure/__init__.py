from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.capabilities import azure_principal_native_id, map_azure_role
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.azure.helpers import call_azure


def _resource_concept(resource_type: str | None) -> ConceptType:
    if resource_type == "KeyVaultSecret":
        return ConceptType.SECRET_STORE
    if resource_type == "StorageAccount":
        return ConceptType.DATA_STORE
    if resource_type == "Identity":
        return ConceptType.IDENTITY
    return ConceptType.DATA_STORE


class AzureIdentityEnumerator:
    concept = ConceptType.IDENTITY
    name = "azure-identity"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        caller_id = ctx.scope.properties.get("native_id", "")
        sub = ctx.scope.properties.get("subscription_id", "")

        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AZURE,
            native_id=caller_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": "ServicePrincipal" if "serviceprincipal" in caller_id else "User",
                "is_caller": True,
                "subscription_id": sub,
                "display_name": caller_id,
            },
            evidence=Evidence("azure:caller", {"native_id": caller_id}),
            confidence=ConfidenceType.EXPLICIT,
        )


class AzureEntitlementEnumerator:
    concept = ConceptType.ENTITLEMENT
    name = "azure-entitlement"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        auth = cred.client("authorization")  # type: ignore[attr-defined]
        role_defs: dict[str, str] = {}

        def role_name(role_definition_id: str) -> str:
            if role_definition_id in role_defs:
                return role_defs[role_definition_id]
            rd = call_azure(
                ctx,
                operation="authorization.roleDefinitions.get",
                call=lambda: auth.role_definitions.get_by_id(role_definition_id),
            )
            name = rd.role_name if rd else role_definition_id.split("/")[-1]
            role_defs[role_definition_id] = name
            return name

        assignments = call_azure(
            ctx,
            operation="authorization.roleAssignments.list",
            call=lambda: list(auth.role_assignments.list_for_subscription()),
        )
        if not assignments:
            return

        for assignment in assignments:
            rname = role_name(assignment.role_definition_id)
            mapping = map_azure_role(rname)
            if not mapping:
                continue
            principal_type = assignment.principal_type or "Unknown"
            principal_id = azure_principal_native_id(principal_type, assignment.principal_id)
            rtype = mapping.resource_type or "Resource"
            target_id = f"{rtype}:*"
            rel = mapping.capability.value
            edge = ConceptEdge(
                rel_type=rel,
                src_native_id=principal_id,
                target_native_id=target_id,
                target_concept_type=_resource_concept(mapping.resource_type),
                props={"role": rname, "scope": assignment.scope},
                confidence=ConfidenceType.WILDCARD,
            )
            yield ConceptArtifact(
                concept_type=ConceptType.ENTITLEMENT,
                provider=CloudProvider.AZURE,
                native_id=f"azure:roleassignment:{assignment.name}",
                scope_id=ctx.scope.scope_id,
                properties={
                    "role_name": rname,
                    "principal_id": assignment.principal_id,
                    "principal_type": principal_type,
                    "scope": assignment.scope,
                },
                evidence=Evidence("authorization.roleAssignments.list", {"role": rname}),
                edges=[edge],
            )


class AzureStorageEnumerator:
    concept = ConceptType.DATA_STORE
    name = "azure-storage"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        storage = cred.client("storage")  # type: ignore[attr-defined]
        accounts = call_azure(
            ctx,
            operation="storage.storageAccounts.list",
            call=lambda: list(storage.storage_accounts.list()),
        )
        if not accounts:
            return
        for account in accounts:
            name = account.name
            native_id = f"StorageAccount:{name}"
            yield ConceptArtifact(
                concept_type=ConceptType.DATA_STORE,
                provider=CloudProvider.AZURE,
                native_id=native_id,
                scope_id=ctx.scope.scope_id,
                properties={
                    "resource_type": "StorageAccount",
                    "account_name": name,
                    "display_name": name,
                    "resource_group": account.id.split("/")[4] if account.id else None,
                },
                evidence=Evidence("storage.storageAccounts.list", {"account": name}),
            )


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
                },
                evidence=Evidence("keyvault.vaults.list", {"vault": vault_name}),
            )

            if not vault_uri:
                continue
            try:
                from azure.keyvault.secrets import SecretClient

                secret_client = SecretClient(vault_url=vault_uri, credential=cred.credential())  # type: ignore[attr-defined]
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
                    evidence=Evidence("keyvault.secrets.list", {"vault": vault_name, "secret": sname}),
                )


AZURE_ENUMERATORS = [
    AzureIdentityEnumerator(),
    AzureEntitlementEnumerator(),
    AzureStorageEnumerator(),
    AzureKeyVaultEnumerator(),
]
