from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot


def build_sample_graph(session_id: str = "sample-lab") -> GraphSnapshot:
    """
    Offline graph for UI/tests. For a live emulated lab, use `samoyed firing-range`.
    Path: leaked user -> assume admin role -> read prod secret.
    """
    builder = GraphBuilder(session_id)

    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:user/leaked-user",
        props={"native_kind": "User", "is_caller": True, "arn": "arn:aws:iam::111111111111:user/leaked-user"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/admin",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/admin"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db",
        props={"resource_type": "Secret", "name": "prod-db"},
    )
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="S3Bucket:prod-data",
        props={"resource_type": "S3Bucket", "bucket_name": "prod-data"},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role, props={"confidence": "explicit"})
    builder.add_edge(src_id=role, rel_type="READS", dst_id=secret, props={"confidence": "explicit"})
    builder.add_edge(src_id=role, rel_type="READS", dst_id=bucket, props={"confidence": "wildcard"})
    # Simulated discovered entitlement — direct IAM privesc (bug bounty / partial enum scenario)
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=user,
        props={"confidence": "explicit", "action": "iam:AttachUserPolicy", "resource": "*"},
    )

    for node_id in (user, role, secret, bucket):
        builder.link_session(node_id)

    apply_attack_analysis(builder, provider=CloudProvider.AWS)
    return builder.snapshot


def load_sample_session_metadata() -> dict[str, Any]:
    return {
        "caller_arn": "arn:aws:iam::111111111111:user/leaked-user",
        "scope_id": "aws:account:111111111111",
        "provider": "aws",
        "artifact_count": 0,
        "node_count": 4,
        "sample": True,
    }
