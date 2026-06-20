from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from samoyed.cloud.concepts import TRAVERSABLE_REL_TYPES, CapabilityType, ConceptType, CloudProvider


@dataclass(frozen=True)
class ConceptMapping:
    concept: ConceptType
    attack_path_role: str
    aws: str = ""
    gcp: str = ""
    azure: str = ""
    kubernetes: str = ""
    docker: str = ""


CONCEPT_MAPPINGS: tuple[ConceptMapping, ...] = (
    ConceptMapping(ConceptType.SCOPE_BOUNDARY, "Account/project isolation", "Account", "Project", "Subscription"),
    ConceptMapping(
        ConceptType.ORCHESTRATION_SCOPE,
        "Cluster/namespace boundary",
        "EKS cluster",
        "GKE cluster",
        "AKS cluster",
        "Cluster/Namespace",
        "Docker host",
    ),
    ConceptMapping(
        ConceptType.IDENTITY,
        "Start node / pivot principal",
        "IAM User/Role",
        "User/SA",
        "User/SP/MI",
        "ServiceAccount",
    ),
    ConceptMapping(
        ConceptType.ENTITLEMENT,
        "Permission grant",
        "IAM PolicyStatement",
        "IAM Binding",
        "Role Assignment",
        "Role/ClusterRole + Binding",
    ),
    ConceptMapping(
        ConceptType.TRUST,
        "Who can become whom",
        "Role trust policy",
        "SA impersonation",
        "Federated identity",
        "SA token projection",
    ),
    ConceptMapping(
        ConceptType.RUNTIME_BINDING,
        "Compromised compute → cloud identity",
        "Instance profile/Lambda role",
        "GCE/Cloud Run SA",
        "VM/App MI",
        "Pod→node cloud IAM (IRSA/WI/MI)",
        "Container→host",
    ),
    ConceptMapping(
        ConceptType.WORKLOAD,
        "Compromised pod/container pivot",
        "EKS Pod",
        "GKE Pod",
        "AKS Pod",
        "Pod/Deployment",
        "Container",
    ),
    ConceptMapping(
        ConceptType.ESCAPE_SURFACE,
        "Container→host escalation",
        "Privileged EKS pod",
        "Privileged GKE pod",
        "Privileged AKS pod",
        "privileged/hostPath/caps",
        "docker.sock/privileged",
    ),
    ConceptMapping(
        ConceptType.IMAGE_PROVENANCE,
        "Supply-chain edge",
        "ECR image URI",
        "GAR image",
        "ACR image",
        "container image:",
        "Image metadata",
    ),
    ConceptMapping(
        ConceptType.REGISTRY_STORE,
        "Supply-chain pivot",
        "ECR",
        "GAR/GCR",
        "ACR",
        "Any registry ref",
        "Docker Hub/private",
    ),
    ConceptMapping(
        ConceptType.MANAGEMENT_ENDPOINT,
        "Control-plane API leak",
        "EKS API via IAM",
        "GKE API",
        "AKS API",
        "K8s API server",
        "Docker daemon",
    ),
    ConceptMapping(
        ConceptType.DATA_STORE,
        "High-value target",
        "S3/RDS",
        "GCS/Cloud SQL",
        "Blob/SQL",
        "PV/ConfigMap",
        "Volume mount",
    ),
    ConceptMapping(
        ConceptType.SECRET_STORE,
        "High-value target",
        "Secrets Manager/SSM",
        "Secret Manager",
        "Key Vault",
        "K8s Secret",
    ),
    ConceptMapping(
        ConceptType.NETWORK_EXPOSURE,
        "Lateral movement",
        "Security groups",
        "Firewall rules",
        "NSGs",
        "NetworkPolicy gaps",
        "Published ports",
    ),
)


CROSS_LAYER_EDGES: tuple[dict[str, str], ...] = (
    {"rel": "HOSTED_IN", "meaning": "Workload/cluster nested in cloud or parent scope"},
    {"rel": "EXECUTES_AS", "meaning": "Runtime uses bound identity (pod SA, instance profile)"},
    {"rel": "PROJECTS_TO", "meaning": "K8s SA projects to cloud IAM role (IRSA/WI/MI)"},
    {"rel": "USES_IMAGE", "meaning": "Workload references container image"},
    {"rel": "PULLS_FROM", "meaning": "Image pulled from registry"},
    {"rel": "HAS_ESCAPE_SURFACE", "meaning": "Workload has container escape misconfiguration"},
    {"rel": "CAN_ESCAPE_TO", "meaning": "Escape surface reaches node/host/cloud runtime"},
    {"rel": "CAN_ACCESS", "meaning": "Identity reaches management API"},
    {"rel": "CAN_ASSUME_ROLE", "meaning": "Trust allows identity→role pivot"},
)


def export_ontology() -> dict[str, Any]:
    return {
        "concepts": [c.value for c in ConceptType],
        "capabilities": [c.value for c in CapabilityType],
        "traversable_relationships": sorted(TRAVERSABLE_REL_TYPES),
        "providers": [p.value for p in CloudProvider],
        "concept_mappings": [
            {
                "concept": m.concept.value,
                "attack_path_role": m.attack_path_role,
                "native_kinds": {
                    "aws": m.aws,
                    "gcp": m.gcp,
                    "azure": m.azure,
                    "kubernetes": m.kubernetes,
                    "docker": m.docker,
                },
            }
            for m in CONCEPT_MAPPINGS
        ],
        "cross_layer_edges": list(CROSS_LAYER_EDGES),
    }
