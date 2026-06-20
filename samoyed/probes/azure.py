from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CapabilityType, CloudProvider, ConceptType
from samoyed.enumerators.azure.helpers import is_azure_denied
from samoyed.probes.models import ApiProbe, ProbeResult

AZURE_PROBE_CATALOG: list[ApiProbe] = [
    ApiProbe("storage.accounts.list", "List storage accounts", CapabilityType.READS, "StorageAccount", concept_type="DataStore", high_value=True),
    ApiProbe("keyvault.vaults.list", "List Key Vaults", CapabilityType.READS, "KeyVault", concept_type="SecretStore", high_value=True),
    ApiProbe("authorization.roleAssignments.list", "List role assignments", CapabilityType.READS, "RoleAssignment", concept_type="Entitlement"),
    ApiProbe("resources.list", "List resources in subscription", CapabilityType.READS, "Resource", concept_type="DataStore"),
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
        if probe.operation == "resources.list":
            from azure.mgmt.resource import ResourceManagementClient

            rm = ResourceManagementClient(cred.credential(), cred.subscription_id)
            resources = list(rm.resources.list()[:50])
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
            if probe.resource_type == "StorageAccount":
                name = resource["name"]
                native_id = f"StorageAccount:{name}"
                concept = ConceptType.DATA_STORE
            elif probe.resource_type == "KeyVault":
                name = resource["name"]
                native_id = f"KeyVault:{name}"
                concept = ConceptType.SECRET_STORE
            else:
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
