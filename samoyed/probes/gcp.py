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
    ApiProbe("resourcemanager.projects.getIamPolicy", "Read project IAM policy", CapabilityType.READS, "IAMPolicy", concept_type="Entitlement", high_value=True),
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
        if probe.operation == "resourcemanager.projects.getIamPolicy":
            rm = cred.client("resourcemanager")
            policy = rm.get_iam_policy(request={"resource": f"projects/{project}"})
            return ProbeResult(
                probe.operation, "allowed",
                resources=[{"project_id": project, "binding_count": len(policy.bindings)}],
            )
        rest_endpoints = {
            "compute.instances.list": (
                f"https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances",
                "items",
            ),
            "cloudfunctions.functions.list": (
                f"https://cloudfunctions.googleapis.com/v2/projects/{project}/locations/-/functions",
                "functions",
            ),
            "container.clusters.list": (
                f"https://container.googleapis.com/v1/projects/{project}/locations/-/clusters",
                "clusters",
            ),
            "artifactregistry.repositories.list": (
                f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations/-/repositories",
                "repositories",
            ),
        }
        if probe.operation in rest_endpoints:
            url, key = rest_endpoints[probe.operation]
            resources = _rest_list(cred, url, key)
            return ProbeResult(probe.operation, "allowed", resources=resources)
        return ProbeResult(probe.operation, "error", message="Unhandled GCP probe")
    except Exception as exc:
        if is_gcp_denied(exc):
            return ProbeResult(probe.operation, "denied", error_code="PermissionDenied", message=str(exc))
        return ProbeResult(probe.operation, "error", message=str(exc))


def _rest_list(cred: Any, url: str, key: str) -> list[dict[str, Any]]:
    from google.auth.transport.requests import AuthorizedSession

    response = AuthorizedSession(cred.credentials()).get(url, timeout=30)
    response.raise_for_status()
    result = response.json().get(key, [])
    if key == "items":
        return [
            {"name": instance.get("name"), "zone": zone}
            for zone, payload in result.items()
            for instance in payload.get("instances", [])
        ]
    return [{"name": value.get("name"), **({"id": value.get("id")} if value.get("id") else {})} for value in result]


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
            elif probe.resource_type in {"GCEInstance", "CloudFunction"}:
                name = resource.get("name", "")
                native_id = f"{probe.resource_type}:{name}"
                concept = ConceptType.RUNTIME_BINDING
            elif probe.resource_type == "GKECluster":
                name = resource.get("name", "")
                native_id = f"GKECluster:{name}"
                concept = ConceptType.ORCHESTRATION_SCOPE
            elif probe.resource_type == "ArtifactRegistry":
                name = resource.get("name", "")
                native_id = f"ArtifactRegistry:{name}"
                concept = ConceptType.REGISTRY_STORE
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
