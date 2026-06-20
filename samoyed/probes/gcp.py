from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CapabilityType, CloudProvider, ConceptType
from samoyed.enumerators.gcp.helpers import is_gcp_denied
from samoyed.probes.models import ApiProbe, ProbeResult

GCP_PROBE_CATALOG: list[ApiProbe] = [
    ApiProbe("storage.buckets.list", "List GCS buckets", CapabilityType.READS, "GCSBucket", concept_type="DataStore", high_value=True),
    ApiProbe("secretmanager.secrets.list", "List Secret Manager secrets", CapabilityType.READS, "GCPSecret", concept_type="SecretStore", high_value=True),
    ApiProbe("iam.serviceAccounts.list", "List service accounts", CapabilityType.READS, "ServiceAccount", concept_type="Identity"),
    ApiProbe("compute.instances.list", "List GCE instances", CapabilityType.READS, "GCEInstance", concept_type="RuntimeBinding"),
    ApiProbe("cloudfunctions.functions.list", "List Cloud Functions", CapabilityType.READS, "CloudFunction", concept_type="RuntimeBinding"),
    ApiProbe("container.clusters.list", "List GKE clusters", CapabilityType.READS, "GKECluster", concept_type="OrchestrationScope", high_value=True),
    ApiProbe("artifactregistry.repositories.list", "List Artifact Registry repos", CapabilityType.READS, "ArtifactRegistry", concept_type="RegistryStore"),
]


def run_gcp_probe(cred: Any, probe: ApiProbe) -> ProbeResult:
    project = cred.project_id
    try:
        if probe.operation == "storage.buckets.list":
            storage = cred.client("storage")
            buckets = list(storage.list_buckets())
            return ProbeResult(
                probe.operation,
                "allowed",
                resources=[{"name": b.name} for b in buckets],
            )
        if probe.operation == "secretmanager.secrets.list":
            sm = cred.client("secretmanager")
            parent = f"projects/{project}"
            secrets = list(sm.list_secrets(request={"parent": parent}))
            return ProbeResult(
                probe.operation,
                "allowed",
                resources=[{"name": s.name, "short_name": s.name.split("/")[-1]} for s in secrets],
            )
        if probe.operation == "iam.serviceAccounts.list":
            iam = cred.client("iam")
            parent = f"projects/{project}"
            sas = list(iam.list_service_accounts(request={"parent": parent}))
            return ProbeResult(
                probe.operation,
                "allowed",
                resources=[{"email": sa.email, "name": sa.name} for sa in sas],
            )
        return ProbeResult(probe.operation, "error", message="Unhandled GCP probe")
    except Exception as exc:
        if is_gcp_denied(exc):
            return ProbeResult(probe.operation, "denied", error_code="PermissionDenied", message=str(exc))
        return ProbeResult(probe.operation, "error", message=str(exc))


def gcp_probe_catalog(*, high_value_only: bool = False) -> list[ApiProbe]:
    if high_value_only:
        return [p for p in GCP_PROBE_CATALOG if p.high_value]
    return list(GCP_PROBE_CATALOG)


def artifacts_from_gcp_probes(
    *,
    scope_id: str,
    caller_id: str,
    results: list[ProbeResult],
) -> Iterator[ConceptArtifact]:
    yield ConceptArtifact(
        concept_type=ConceptType.IDENTITY,
        provider=CloudProvider.GCP,
        native_id=caller_id,
        scope_id=scope_id,
        properties={"native_kind": "ServiceAccount", "is_caller": True, "discovered_via": "probe"},
        evidence=Evidence("probe:caller", {}),
    )
    for result in results:
        if result.status != "allowed":
            continue
        probe = next((p for p in GCP_PROBE_CATALOG if p.operation == result.operation), None)
        if not probe:
            continue
        for resource in result.resources:
            if probe.resource_type == "GCSBucket":
                name = resource["name"]
                native_id = f"GCSBucket:{name}"
                concept = ConceptType.DATA_STORE
            elif probe.resource_type == "GCPSecret":
                name = resource.get("name", "")
                native_id = f"GCPSecret:{name}"
                concept = ConceptType.SECRET_STORE
            elif probe.resource_type == "ServiceAccount":
                email = resource.get("email", "")
                native_id = f"gcp:serviceaccount:{email}"
                concept = ConceptType.IDENTITY
            else:
                continue
            yield ConceptArtifact(
                concept_type=concept,
                provider=CloudProvider.GCP,
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
