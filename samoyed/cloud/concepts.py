from __future__ import annotations

from enum import Enum


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"


class ConceptType(str, Enum):
    SCOPE_BOUNDARY = "ScopeBoundary"
    ORCHESTRATION_SCOPE = "OrchestrationScope"
    NETWORK_BOUNDARY = "NetworkBoundary"
    IDENTITY = "Identity"
    ENTITLEMENT = "Entitlement"
    TRUST = "Trust"
    RUNTIME_BINDING = "RuntimeBinding"
    WORKLOAD = "Workload"
    IMAGE_PROVENANCE = "ImageProvenance"
    REGISTRY_STORE = "RegistryStore"
    MANAGEMENT_ENDPOINT = "ManagementEndpoint"
    DATA_STORE = "DataStore"
    SECRET_STORE = "SecretStore"
    NETWORK_EXPOSURE = "NetworkExposure"
    ATTACK_OUTCOME = "AttackOutcome"


# Graph node labels derived from concepts (L0)
CONCEPT_TO_NODE_LABEL: dict[ConceptType, str] = {
    ConceptType.SCOPE_BOUNDARY: "ScopeBoundary",
    ConceptType.ORCHESTRATION_SCOPE: "ScopeBoundary",
    ConceptType.NETWORK_BOUNDARY: "NetworkBoundary",
    ConceptType.IDENTITY: "Principal",
    ConceptType.ENTITLEMENT: "PolicyStatement",
    ConceptType.RUNTIME_BINDING: "ComputeContext",
    ConceptType.WORKLOAD: "ComputeContext",
    ConceptType.DATA_STORE: "Resource",
    ConceptType.SECRET_STORE: "Resource",
    ConceptType.REGISTRY_STORE: "Resource",
    ConceptType.MANAGEMENT_ENDPOINT: "Resource",
    ConceptType.IMAGE_PROVENANCE: "Resource",
    ConceptType.NETWORK_EXPOSURE: "Resource",
    ConceptType.ATTACK_OUTCOME: "AttackOutcome",
}


class CapabilityType(str, Enum):
    READS = "READS"
    WRITES = "WRITES"
    DELETES = "DELETES"
    CONTROLS = "CONTROLS"
    EXECUTES = "EXECUTES"


class ConfidenceType(str, Enum):
    EXPLICIT = "explicit"
    WILDCARD = "wildcard"
    UNKNOWN_CONDITIONS = "unknown-conditions"


TRAVERSABLE_REL_TYPES = frozenset(
    {
        "CAN_ASSUME_ROLE",
        "EXECUTES_AS",
        "READS",
        "WRITES",
        "DELETES",
        "CONTROLS",
        "EXECUTES",
        "CAN_REACH",
        "VPC_PEERS",
        "BRIDGES_TO",
        "CAN_ESCAPE_TO",
        "USES_IMAGE",
        "PULLS_FROM",
        "DEPENDS_ON",
        "FEEDS",
        "CAN_ACCESS",
        "PROJECTS_TO",
        "HOSTED_IN",
        "CAN_PRIVESC_TO",
        "LOGGED_IN_AS",
        "STORES_CREDS_FOR",
        "CAN_STEAL_CREDS_FROM",
        "HAS_MATERIAL",
        "UNLOCKS",
    }
)
