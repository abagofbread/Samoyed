from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.azure import mi_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.azure.helpers import call_azure
from samoyed.enumerators.azure.targets import resource_group_from_id


class AzureComputeEnumerator:
    concept = ConceptType.RUNTIME_BINDING
    name = "azure-compute"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        yield from _enumerate_vms(ctx)
        yield from _enumerate_web_apps(ctx)
        yield from _enumerate_automation(ctx)


def _enumerate_vms(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    try:
        compute = cred.client("compute")  # type: ignore[attr-defined]
    except ImportError:
        return

    vms = call_azure(
        ctx,
        operation="compute.virtualMachines.listAll",
        call=lambda: list(compute.virtual_machines.list_all()),
    )
    if not vms:
        return

    for vm in vms:
        name = getattr(vm, "name", None) or "unknown"
        native_id = f"AzureVM:{name}"
        mi_ids = _identity_principal_ids(getattr(vm, "identity", None))
        yield from _mi_identity_stubs(ctx, mi_ids)
        edges = _executes_as_edges(mi_ids, "AzureVM")
        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AZURE,
            native_id=native_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "resource_type": "AzureVM",
                "name": name,
                "display_name": name,
                "resource_group": resource_group_from_id(getattr(vm, "id", None)),
                "resource_id": getattr(vm, "id", None),
                "execution_identities": [mi_native_id(p) for p in mi_ids],
            },
            evidence=Evidence("compute.virtualMachines.listAll", {"name": name}),
            edges=edges,
        )


def _enumerate_web_apps(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    try:
        web = cred.client("web")  # type: ignore[attr-defined]
    except ImportError:
        return

    apps = call_azure(
        ctx,
        operation="web.webApps.list",
        call=lambda: list(web.web_apps.list()),
    )
    if not apps:
        return

    for app in apps:
        name = getattr(app, "name", None) or "unknown"
        kind = (getattr(app, "kind", None) or "").lower()
        resource_type = "FunctionApp" if "functionapp" in kind else "WebApp"
        native_id = f"{resource_type}:{name}"
        mi_ids = _identity_principal_ids(getattr(app, "identity", None))
        yield from _mi_identity_stubs(ctx, mi_ids)
        edges = _executes_as_edges(mi_ids, resource_type)
        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AZURE,
            native_id=native_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "resource_type": resource_type,
                "name": name,
                "display_name": name,
                "kind": getattr(app, "kind", None),
                "resource_group": resource_group_from_id(getattr(app, "id", None)),
                "resource_id": getattr(app, "id", None),
                "execution_identities": [mi_native_id(p) for p in mi_ids],
            },
            evidence=Evidence("web.webApps.list", {"name": name, "kind": kind}),
            edges=edges,
        )


def _enumerate_automation(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    try:
        automation = cred.client("automation")  # type: ignore[attr-defined]
    except ImportError:
        return

    accounts = call_azure(
        ctx,
        operation="automation.automationAccount.list",
        call=lambda: list(automation.automation_account.list()),
    )
    if not accounts:
        return

    for account in accounts:
        name = getattr(account, "name", None) or "unknown"
        native_id = f"AutomationAccount:{name}"
        # identity may be on the account or require a get; best-effort from list payload
        identity = getattr(account, "identity", None)
        if identity is None:
            rg = resource_group_from_id(getattr(account, "id", None))
            if rg and name:
                detailed = call_azure(
                    ctx,
                    operation=f"automation.automationAccount.get:{name}",
                    call=lambda rg=rg, n=name: automation.automation_account.get(rg, n),
                )
                identity = getattr(detailed, "identity", None) if detailed else None
        mi_ids = _identity_principal_ids(identity)
        yield from _mi_identity_stubs(ctx, mi_ids)
        edges = _executes_as_edges(mi_ids, "AutomationAccount")
        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AZURE,
            native_id=native_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "resource_type": "AutomationAccount",
                "name": name,
                "display_name": name,
                "resource_group": resource_group_from_id(getattr(account, "id", None)),
                "resource_id": getattr(account, "id", None),
                "execution_identities": [mi_native_id(p) for p in mi_ids],
            },
            evidence=Evidence("automation.automationAccount.list", {"name": name}),
            edges=edges,
        )


def _identity_principal_ids(identity: Any) -> list[str]:
    """Extract system-assigned + user-assigned principal IDs from an ARM identity block."""
    if not identity:
        return []
    out: list[str] = []
    principal = getattr(identity, "principal_id", None)
    if principal:
        out.append(str(principal))
    # user_assigned_identities: dict[arm_id, UserAssignedIdentity] with principal_id
    uai = getattr(identity, "user_assigned_identities", None) or {}
    if isinstance(uai, dict):
        for _arm_id, meta in uai.items():
            pid = getattr(meta, "principal_id", None) if meta is not None else None
            if pid is None and isinstance(meta, dict):
                pid = meta.get("principal_id")
            if pid:
                out.append(str(pid))
    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def _executes_as_edges(principal_ids: list[str], resource_type: str) -> list[ConceptEdge]:
    edges: list[ConceptEdge] = []
    for pid in principal_ids:
        edges.append(
            ConceptEdge(
                rel_type="EXECUTES_AS",
                target_native_id=mi_native_id(pid),
                target_concept_type=ConceptType.IDENTITY,
                props={
                    "principal_id": pid,
                    "resource_type": resource_type,
                    "mechanism": "managed-identity",
                },
            )
        )
    return edges


def _mi_identity_stubs(ctx: EnumContext, principal_ids: list[str]) -> Iterator[ConceptArtifact]:
    """Emit Identity nodes for system/user-assigned MIs attached to runtimes."""
    sub = ctx.scope.properties.get("subscription_id")
    for pid in principal_ids:
        native_id = mi_native_id(pid)
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AZURE,
            native_id=native_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": "ManagedIdentity",
                "principal_id": pid,
                "display_name": native_id,
                "subscription_id": sub,
            },
            evidence=Evidence("azure:managed-identity", {"principal_id": pid}),
        )
