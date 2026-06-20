from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot


def build_sample_azure_graph(session_id: str = "sample-azure") -> GraphSnapshot:
    """Offline Azure graph: leaked SP → Key Vault secret + storage account."""
    builder = GraphBuilder(session_id)
    leaked = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="azure:serviceprincipal:11111111-1111-1111-1111-111111111111",
        props={
            "native_kind": "ServicePrincipal",
            "client_id": "11111111-1111-1111-1111-111111111111",
            "is_caller": True,
            "display_name": "leaked-app-sp",
        },
    )
    admin = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="azure:serviceprincipal:22222222-2222-2222-2222-222222222222",
        props={"native_kind": "ServicePrincipal", "display_name": "admin-sp"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="KeyVaultSecret:prod-vault/db-connection-string",
        props={"resource_type": "KeyVaultSecret", "vault_name": "prod-vault", "secret_name": "db-connection-string"},
    )
    storage = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="StorageAccount:proddatastore",
        props={"resource_type": "StorageAccount", "account_name": "proddatastore"},
    )
    builder.add_edge(src_id=leaked, rel_type="READS", dst_id=secret, props={"role": "Key Vault Secrets User"})
    builder.add_edge(src_id=leaked, rel_type="READS", dst_id=storage, props={"role": "Storage Blob Data Reader"})
    builder.add_edge(src_id=leaked, rel_type="CAN_ASSUME_ROLE", dst_id=admin, props={"role": "User Access Administrator"})
    builder.add_edge(src_id=admin, rel_type="CONTROLS", dst_id=secret, props={"role": "Key Vault Administrator"})
    for node_id in (leaked, admin, secret, storage):
        builder.link_session(node_id)
    return builder.snapshot


def load_sample_azure_session_metadata() -> dict[str, Any]:
    return {
        "caller_arn": "azure:serviceprincipal:11111111-1111-1111-1111-111111111111",
        "scope_id": "azure:subscription:33333333-3333-3333-3333-333333333333",
        "provider": "azure",
        "artifact_count": 0,
        "node_count": 4,
        "sample": True,
        "platform": "azure",
    }
