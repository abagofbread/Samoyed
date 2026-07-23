"""SkyArk FullS3Admin / FullKMSAdmin service-admin tests."""

from __future__ import annotations

from samoyed.attack.outcomes import KMS_ADMIN_OUTCOME_TYPE, S3_ADMIN_OUTCOME_TYPE
from samoyed.attack.service_admin import enrich_service_admins
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import is_high_value
from samoyed.path_engine.search import find_attack_paths


def test_full_s3_admin_marked_and_pathable():
    builder = GraphBuilder("svc-s3")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/data-lake-ops",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/data-lake-ops",
            "name": "data-lake-ops",
            "provider": "aws",
        },
    )
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="pol:s3star",
        props={
            "principal_arn": "arn:aws:iam::1:role/data-lake-ops",
            "policy_name": "DataLakeAdmin",
            "actions": ["s3:*"],
            "resources": ["*"],
        },
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=role,
        props={"action": "s3:*", "resource": "*"},
    )

    stats = enrich_service_admins(builder, provider=CloudProvider.AWS)
    assert stats["service_admins_marked"] >= 1
    assert is_high_value(builder.snapshot.nodes[role].props)
    assert "full-s3-admin" in (builder.snapshot.nodes[role].props.get("service_admin_kinds") or [])

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=role,
        target_resource_type=S3_ADMIN_OUTCOME_TYPE,
        max_depth=3,
    )
    assert paths
    assert any(s.rel_type == "CAN_PRIVESC_TO" for s in paths[0].steps)


def test_full_kms_admin_distinct_from_account_admin():
    builder = GraphBuilder("svc-kms")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/crypto-ops",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/crypto-ops",
            "name": "crypto-ops",
            "provider": "aws",
        },
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=role,
        props={"action": "kms:*", "resource": "*"},
    )
    enrich_service_admins(builder, provider=CloudProvider.AWS)
    props = builder.snapshot.nodes[role].props
    assert is_high_value(props)
    assert props.get("high_value_kind") == "full-kms-admin"
    # Not a full-account shadow/admin outcome by itself
    assert props.get("high_value_kind") != "administrator-wildcard"

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=role,
        target_resource_type=KMS_ADMIN_OUTCOME_TYPE,
        max_depth=2,
    )
    assert paths
