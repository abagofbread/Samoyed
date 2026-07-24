from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CapabilityType, CloudProvider, ConceptType
from samoyed.enumerators.azure.helpers import is_azure_denied
from samoyed.probes.models import ApiProbe, ProbeResult

AZURE_PROBE_CATALOG: list[ApiProbe] = [
    ApiProbe(
        "storage.accounts.list",
        "List storage accounts",
        CapabilityType.READS,
        "StorageAccount",
        concept_type="DataStore",
        high_value=True,
    ),
    ApiProbe(
        "keyvault.vaults.list",
        "List Key Vaults",
        CapabilityType.READS,
        "KeyVault",
        concept_type="SecretStore",
        high_value=True,
    ),
    ApiProbe(
        "authorization.roleAssignments.list",
        "List role assignments",
        CapabilityType.READS,
        "RoleAssignment",
        concept_type="Entitlement",
    ),
    ApiProbe(
        "compute.virtualMachines.list",
        "List virtual machines",
        CapabilityType.READS,
        "AzureVM",
        concept_type="RuntimeBinding",
    ),
    ApiProbe(
        "web.sites.list",
        "List App Service web apps",
        CapabilityType.READS,
        "WebApp",
        concept_type="RuntimeBinding",
    ),
    ApiProbe(
        "containerregistry.registries.list",
        "List Azure Container Registries",
        CapabilityType.READS,
        "AcrRegistry",
        concept_type="RegistryStore",
        high_value=True,
    ),
    ApiProbe(
        "msi.federatedIdentityCredentials.list",
        "List federated identity credentials on user-assigned MIs",
        CapabilityType.READS,
        "FederatedCredential",
        concept_type="Trust",
    ),
    ApiProbe(
        "resources.list",
        "List resources in subscription",
        CapabilityType.READS,
        "Resource",
        concept_type="DataStore",
    ),
]


def run_azure_probe(cred: Any, probe: ApiProbe) -> ProbeResult:
    try:
        if probe.operation == "storage.accounts.list":
            storage = cred.client("storage")
            accounts = list(storage.storage_accounts.list())
            return ProbeResult(
                probe.operation,
                "allowed",
                resources=[{"name": a.name, "id": a.id} for a in accounts],
            )
        if probe.operation == "keyvault.vaults.list":
            kv = cred.client("keyvault")
            vaults = list(kv.vaults.list())
            return ProbeResult(
                probe.operation,
                "allowed",
                resources=[{"name": v.name, "uri": getattr(v.properties, "vault_uri", None)} for v in vaults],
            )
        if probe.operation == "authorization.roleAssignments.list":
            auth = cred.client("authorization")
            assignments = list(auth.role_assignments.list_for_subscription())
            return ProbeResult(
                probe.operation,
                "allowed",
                resources=[
                    {
                        "name": a.name,
                        "role_definition_id": a.role_definition_id,
                        "principal_id": a.principal_id,
                    }
                    for a in assignments[:50]
                ],
            )
        if probe.operation == "compute.virtualMachines.list":
            return _list_compute_vms(cred)
        if probe.operation == "web.sites.list":
            return _list_web_apps(cred)
        if probe.operation == "containerregistry.registries.list":
            return _list_acr_registries(cred)
        if probe.operation == "msi.federatedIdentityCredentials.list":
            return _list_federated_credentials(cred)
        if probe.operation == "resources.list":
            from azure.mgmt.resource import ResourceManagementClient

            rm = ResourceManagementClient(cred.credential(), cred.subscription_id)
            resources = list(rm.resources.list())[:50]
            return ProbeResult(
                probe.operation,
                "allowed",
                resources=[{"name": r.name, "type": r.type, "id": r.id} for r in resources],
            )
        return ProbeResult(probe.operation, "error", message="Unhandled Azure probe")
    except Exception as exc:
        if is_azure_denied(exc):
            return ProbeResult(probe.operation, "denied", error_code="AuthorizationFailed", message=str(exc))
        return ProbeResult(probe.operation, "error", message=str(exc))


def _list_compute_vms(cred: Any) -> ProbeResult:
    try:
        from azure.mgmt.compute import ComputeManagementClient

        compute = ComputeManagementClient(cred.credential(), cred.subscription_id)
        vms = list(compute.virtual_machines.list_all())
        return ProbeResult(
            "compute.virtualMachines.list",
            "allowed",
            resources=[{"name": vm.name, "id": vm.id} for vm in vms[:50]],
        )
    except ImportError:
        return _list_resources_by_type(
            cred,
            "compute.virtualMachines.list",
            "Microsoft.Compute/virtualMachines",
            name_key="name",
        )


def _list_web_apps(cred: Any) -> ProbeResult:
    try:
        from azure.mgmt.web import WebSiteManagementClient

        web = WebSiteManagementClient(cred.credential(), cred.subscription_id)
        sites = list(web.web_apps.list())
        return ProbeResult(
            "web.sites.list",
            "allowed",
            resources=[{"name": s.name, "id": s.id} for s in sites[:50]],
        )
    except ImportError:
        return _list_resources_by_type(
            cred,
            "web.sites.list",
            "Microsoft.Web/sites",
            name_key="name",
        )


def _list_acr_registries(cred: Any) -> ProbeResult:
    try:
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient

        acr = ContainerRegistryManagementClient(cred.credential(), cred.subscription_id)
        regs = list(acr.registries.list())
        return ProbeResult(
            "containerregistry.registries.list",
            "allowed",
            resources=[{"name": r.name, "id": r.id} for r in regs[:50]],
        )
    except ImportError:
        return _list_resources_by_type(
            cred,
            "containerregistry.registries.list",
            "Microsoft.ContainerRegistry/registries",
            name_key="name",
        )


def _list_federated_credentials(cred: Any) -> ProbeResult:
    """Best-effort: federated identity credentials on user-assigned managed identities."""
    try:
        from azure.mgmt.msi import ManagedServiceIdentityClient
    except ImportError:
        return ProbeResult(
            "msi.federatedIdentityCredentials.list",
            "denied",
            error_code="ProbeSkipped",
            message="Install azure-mgmt-msi (samoyed[azure])",
        )

    msi = ManagedServiceIdentityClient(cred.credential(), cred.subscription_id)
    resources: list[dict[str, Any]] = []
    try:
        identities = list(msi.user_assigned_identities.list_by_subscription())
    except Exception as exc:
        if is_azure_denied(exc):
            return ProbeResult(
                "msi.federatedIdentityCredentials.list",
                "denied",
                error_code="AuthorizationFailed",
                message=str(exc),
            )
        raise

    for identity in identities[:25]:
        resource_group = _resource_group_from_id(getattr(identity, "id", "") or "")
        name = getattr(identity, "name", None)
        if not resource_group or not name:
            continue
        try:
            fics = list(
                msi.federated_identity_credentials.list(resource_group, name)
            )
        except Exception:
            continue
        for fic in fics:
            resources.append(
                {
                    "name": getattr(fic, "name", None),
                    "identity": name,
                    "issuer": getattr(fic, "issuer", None),
                    "subject": getattr(fic, "subject", None),
                    "audiences": list(getattr(fic, "audiences", None) or []),
                }
            )
            if len(resources) >= 50:
                break
        if len(resources) >= 50:
            break

    return ProbeResult(
        "msi.federatedIdentityCredentials.list",
        "allowed",
        resources=resources,
    )


def _list_resources_by_type(cred: Any, operation: str, azure_type: str, *, name_key: str) -> ProbeResult:
    from azure.mgmt.resource import ResourceManagementClient

    rm = ResourceManagementClient(cred.credential(), cred.subscription_id)
    resources = [
        {"name": getattr(r, name_key, None), "id": r.id, "type": r.type}
        for r in rm.resources.list()
        if (r.type or "").lower() == azure_type.lower()
    ][:50]
    return ProbeResult(operation, "allowed", resources=resources)


def _resource_group_from_id(resource_id: str) -> str | None:
    parts = resource_id.strip("/").split("/")
    for idx, part in enumerate(parts):
        if part.lower() == "resourcegroups" and idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def azure_probe_catalog(*, high_value_only: bool = False) -> list[ApiProbe]:
    if high_value_only:
        return [p for p in AZURE_PROBE_CATALOG if p.high_value]
    return list(AZURE_PROBE_CATALOG)


def artifacts_from_azure_probes(
    *,
    scope_id: str,
    caller_id: str,
    results: list[ProbeResult],
) -> Iterator[ConceptArtifact]:
    yield ConceptArtifact(
        concept_type=ConceptType.IDENTITY,
        provider=CloudProvider.AZURE,
        native_id=caller_id,
        scope_id=scope_id,
        properties={"native_kind": "ServicePrincipal", "is_caller": True, "discovered_via": "probe"},
        evidence=Evidence("probe:caller", {}),
    )
    for result in results:
        if result.status != "allowed":
            continue
        probe = next((p for p in AZURE_PROBE_CATALOG if p.operation == result.operation), None)
        if not probe:
            continue
        for resource in result.resources:
            native_id, concept = _native_for_probe_resource(probe, resource)
            if not native_id or concept is None:
                continue
            yield ConceptArtifact(
                concept_type=concept,
                provider=CloudProvider.AZURE,
                native_id=native_id,
                scope_id=scope_id,
                properties={"discovered_via": "probe", **resource},
                evidence=Evidence(result.operation, resource),
                edges=[
                    ConceptEdge(
                        rel_type=probe.capability.value,
                        src_native_id=caller_id,
                        target_native_id=native_id,
                        target_concept_type=concept,
                        props={"operation": result.operation, "inferred": True},
                    )
                ],
            )


def _native_for_probe_resource(
    probe: ApiProbe, resource: dict[str, Any]
) -> tuple[str | None, ConceptType | None]:
    name = resource.get("name")
    if not name and probe.resource_type != "FederatedCredential":
        return None, None
    if probe.resource_type == "StorageAccount":
        return f"StorageAccount:{name}", ConceptType.DATA_STORE
    if probe.resource_type == "KeyVault":
        return f"KeyVault:{name}", ConceptType.SECRET_STORE
    if probe.resource_type == "AzureVM":
        return f"AzureVM:{name}", ConceptType.RUNTIME_BINDING
    if probe.resource_type == "WebApp":
        return f"WebApp:{name}", ConceptType.RUNTIME_BINDING
    if probe.resource_type == "AcrRegistry":
        return f"AcrRegistry:{name}", ConceptType.REGISTRY_STORE
    if probe.resource_type == "FederatedCredential":
        identity = resource.get("identity") or "unknown"
        fic = name or resource.get("subject") or "fic"
        return f"azure:federatedcredential:{identity}/{fic}", ConceptType.TRUST
    return None, None
