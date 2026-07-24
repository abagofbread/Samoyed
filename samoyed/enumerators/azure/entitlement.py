from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.capabilities import azure_principal_native_id, map_azure_role
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.azure.helpers import call_azure
from samoyed.enumerators.azure.targets import targets_for_assignment


def _resource_concept(resource_type: str | None) -> ConceptType:
    if resource_type in {"KeyVaultSecret", "KeyVault"}:
        return ConceptType.SECRET_STORE
    if resource_type == "StorageAccount":
        return ConceptType.DATA_STORE
    if resource_type == "Identity":
        return ConceptType.IDENTITY
    if resource_type in {"AzureVM", "WebApp", "FunctionApp", "AutomationAccount"}:
        return ConceptType.RUNTIME_BINDING
    return ConceptType.DATA_STORE


def _concept_for_target(target_id: str, mapping_resource_type: str | None) -> ConceptType:
    prefix = target_id.split(":", 1)[0]
    if prefix.endswith("*") or not prefix:
        return _resource_concept(mapping_resource_type)
    return _resource_concept(prefix if prefix != mapping_resource_type else mapping_resource_type)


def _collect_inventored_ids(ctx: EnumContext) -> set[str]:
    """Best-effort inventory of native_ids for concrete entitlement targeting."""
    inventored: set[str] = set()
    cred = ctx.credentials

    try:
        storage = cred.client("storage")  # type: ignore[attr-defined]
        accounts = call_azure(
            ctx,
            operation="storage.storageAccounts.list",
            call=lambda: list(storage.storage_accounts.list()),
        )
        for account in accounts or []:
            if getattr(account, "name", None):
                inventored.add(f"StorageAccount:{account.name}")
    except Exception:
        pass

    try:
        kv_mgmt = cred.client("keyvault")  # type: ignore[attr-defined]
        vaults = call_azure(
            ctx,
            operation="keyvault.vaults.list",
            call=lambda: list(kv_mgmt.vaults.list()),
        )
        for vault in vaults or []:
            if getattr(vault, "name", None):
                inventored.add(f"KeyVault:{vault.name}")
    except Exception:
        pass

    try:
        compute = cred.client("compute")  # type: ignore[attr-defined]
        vms = call_azure(
            ctx,
            operation="compute.virtualMachines.listAll",
            call=lambda: list(compute.virtual_machines.list_all()),
        )
        for vm in vms or []:
            if getattr(vm, "name", None):
                inventored.add(f"AzureVM:{vm.name}")
    except Exception:
        pass

    try:
        web = cred.client("web")  # type: ignore[attr-defined]
        apps = call_azure(
            ctx,
            operation="web.webApps.list",
            call=lambda: list(web.web_apps.list()),
        )
        for app in apps or []:
            name = getattr(app, "name", None)
            if not name:
                continue
            kind = (getattr(app, "kind", None) or "").lower()
            if "functionapp" in kind:
                inventored.add(f"FunctionApp:{name}")
            else:
                inventored.add(f"WebApp:{name}")
    except Exception:
        pass

    try:
        automation = cred.client("automation")  # type: ignore[attr-defined]
        accounts = call_azure(
            ctx,
            operation="automation.automationAccount.list",
            call=lambda: list(automation.automation_account.list()),
        )
        for account in accounts or []:
            if getattr(account, "name", None):
                inventored.add(f"AutomationAccount:{account.name}")
    except Exception:
        pass

    return inventored


class AzureEntitlementEnumerator:
    concept = ConceptType.ENTITLEMENT
    name = "azure-entitlement"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        auth = cred.client("authorization")  # type: ignore[attr-defined]
        role_defs: dict[str, str] = {}
        inventored = _collect_inventored_ids(ctx)
        seen_principals: set[str] = set()

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

            if principal_id not in seen_principals:
                seen_principals.add(principal_id)
                yield ConceptArtifact(
                    concept_type=ConceptType.IDENTITY,
                    provider=CloudProvider.AZURE,
                    native_id=principal_id,
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "native_kind": str(principal_type),
                        "principal_id": assignment.principal_id,
                        "display_name": principal_id,
                        "subscription_id": ctx.scope.properties.get("subscription_id"),
                    },
                    evidence=Evidence(
                        "authorization.roleAssignments.list",
                        {"principal_id": assignment.principal_id},
                    ),
                )

            targets = targets_for_assignment(assignment.scope, mapping, inventored)
            edges: list[ConceptEdge] = []
            for target_id, rel in targets:
                edges.append(
                    ConceptEdge(
                        rel_type=rel,
                        src_native_id=principal_id,
                        target_native_id=target_id,
                        target_concept_type=_concept_for_target(
                            target_id, mapping.resource_type
                        ),
                        props={"role": rname, "scope": assignment.scope},
                        confidence=(
                            ConfidenceType.EXPLICIT
                            if "*" not in target_id
                            else ConfidenceType.WILDCARD
                        ),
                    )
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
                edges=edges,
            )
