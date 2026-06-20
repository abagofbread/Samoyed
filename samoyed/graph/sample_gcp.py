from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot


def build_sample_gcp_graph(session_id: str = "sample-gcp") -> GraphSnapshot:
    """Offline GCP graph: leaked SA → secrets + GCS; admin SA impersonation pivot."""
    builder = GraphBuilder(session_id)
    leaked = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="gcp:serviceaccount:leaked-sa@demo-project.iam.gserviceaccount.com",
        props={
            "native_kind": "ServiceAccount",
            "email": "leaked-sa@demo-project.iam.gserviceaccount.com",
            "is_caller": True,
            "display_name": "leaked-sa",
        },
    )
    admin = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="gcp:serviceaccount:admin-sa@demo-project.iam.gserviceaccount.com",
        props={"native_kind": "ServiceAccount", "email": "admin-sa@demo-project.iam.gserviceaccount.com"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="GCPSecret:projects/demo-project/secrets/prod-db",
        props={"resource_type": "GCPSecret", "name": "prod-db"},
    )
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="GCSBucket:prod-data",
        props={"resource_type": "GCSBucket", "bucket_name": "prod-data"},
    )
    builder.add_edge(src_id=leaked, rel_type="READS", dst_id=secret, props={"role": "roles/secretmanager.secretAccessor"})
    builder.add_edge(src_id=leaked, rel_type="READS", dst_id=bucket, props={"role": "roles/storage.objectViewer"})
    builder.add_edge(
        src_id=leaked,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=admin,
        props={"role": "roles/iam.serviceAccountUser"},
    )
    builder.add_edge(src_id=admin, rel_type="READS", dst_id=secret, props={"role": "roles/secretmanager.admin"})
    for node_id in (leaked, admin, secret, bucket):
        builder.link_session(node_id)
    return builder.snapshot


def load_sample_gcp_session_metadata() -> dict[str, Any]:
    return {
        "caller_arn": "gcp:serviceaccount:leaked-sa@demo-project.iam.gserviceaccount.com",
        "scope_id": "gcp:project:demo-project",
        "provider": "gcp",
        "artifact_count": 0,
        "node_count": 4,
        "sample": True,
        "platform": "gcp",
    }
