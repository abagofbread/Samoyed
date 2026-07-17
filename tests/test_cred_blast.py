"""DB password materials must unlock the RDS instance — not secret names."""

from __future__ import annotations

from samoyed.cloud.concepts import ConceptType
from samoyed.enrichment.apply import apply_enrichment_report
from samoyed.enrichment.impact import repair_credential_impact
from samoyed.enrichment.labels import material_summary
from samoyed.graph.builder import GraphBuilder
from samoyed.path_engine.search import get_blast_radius


def _password_report(**extra):
    material = {
        "kind": "generic_credential_file",
        "locator": "modules/module-2/main.tf:476",
        "finding": "Hardcoded password",
        "name_hints": ["RDS_CREDS", "aws-goat-db", "ecs-task-role"],
        "impact_targets": [
            {"name": "aws-goat-db", "kind": "db_instance"},
        ],
        "confidence": "explicit",
        "evidence": {
            "file": "modules/module-2/main.tf",
            "line": 476,
            "match": 'password = "***"',
            "finding": "Hardcoded password",
        },
    }
    material.update(extra)
    return {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "host_hint": "bastion",
        "declared_resources": [
            {
                "kind": "db_instance",
                "name": "aws-goat-db",
                "tf_address": "aws_db_instance.database-instance",
                "source": "main.tf",
            },
            {
                "kind": "secretsmanager_secret",
                "name": "RDS_CREDS",
                "tf_address": "aws_secretsmanager_secret.rds_creds",
                "source": "main.tf",
            },
            {
                "kind": "iam_role",
                "name": "ecs-task-role",
                "tf_address": "aws_iam_role.ecs-task-role",
                "source": "main.tf",
            },
        ],
        "bindings": [{"target_ref": "bastion", "materials": [material]}],
    }


def test_rds_creds_is_not_a_database():
    from samoyed.enrichment.impact import classify_db_hint

    assert classify_db_hint("aws-goat-db") is True
    assert classify_db_hint("RDS_CREDS") is False
    assert classify_db_hint("ecs-task-role") is False


def test_password_label_points_at_rds_not_secret_name():
    summary = material_summary(
        kind="generic_credential_file",
        locator="main.tf:138",
        evidence={"file": "main.tf", "line": 138, "match": 'password = "***"'},
        name_hints=["RDS_CREDS", "aws-goat-db", "ecs-task-role"],
    )
    assert "aws-goat-db" in summary
    assert "RDS_CREDS" not in summary


def test_db_password_unlocks_rds_and_shows_in_blast():
    builder = GraphBuilder("db-cred-blast")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:bastion",
        props={"resource_type": "EC2Instance", "name": "bastion", "display_name": "bastion"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:RDS_CREDS",
        props={"resource_type": "Secret", "name": "RDS_CREDS", "display_name": "RDS_CREDS"},
    )
    rds = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="RDSInstance:aws-goat-db",
        props={
            "resource_type": "RDSInstance",
            "name": "aws-goat-db",
            "display_name": "aws-goat-db",
            "db_instance_identifier": "aws-goat-db",
        },
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={"native_kind": "Role", "name": "ecs-task-role", "display_name": "ecs-task-role"},
    )

    stats = apply_enrichment_report(builder, _password_report())
    assert stats["unlocks_applied"] >= 1

    unlocks = [e for e in builder.snapshot.edges if e.rel_type == "UNLOCKS"]
    unlocked = {e.dst_id for e in unlocks}
    assert rds in unlocked
    assert secret not in unlocked, "password must unlock RDS, not RDS_CREDS secret"
    assert role not in unlocked

    blast = get_blast_radius(builder.snapshot, start_node_id=host, max_depth=4, max_paths=20)
    endpoints = {p.node_ids[-1] for p in blast}
    assert rds in endpoints, f"expected RDS in blast, got {endpoints}"


def test_db_password_projects_rds_when_enum_missing():
    builder = GraphBuilder("db-cred-project")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:bastion",
        props={"resource_type": "EC2Instance", "name": "bastion", "display_name": "bastion"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={
            "native_kind": "Role",
            "name": "ecs-instance-role",
            "display_name": "ecs-instance-role",
        },
    )

    stats = apply_enrichment_report(builder, _password_report())
    assert stats["stores_projected"] >= 1
    assert stats["unlocks_applied"] >= 1

    rds_nodes = [
        n
        for n in builder.snapshot.nodes.values()
        if n.props.get("resource_type") == "RDSInstance"
        or n.props.get("db_instance_identifier") == "aws-goat-db"
    ]
    assert rds_nodes
    unlock_dsts = {e.dst_id for e in builder.snapshot.edges if e.rel_type == "UNLOCKS"}
    assert any(n.node_id in unlock_dsts for n in rds_nodes)
    assert role not in unlock_dsts
    assert not any("RDS_CREDS" in d for d in unlock_dsts)

    blast = get_blast_radius(builder.snapshot, start_node_id=host, max_depth=4, max_paths=30)
    endpoints = {p.node_ids[-1] for p in blast}
    assert any(n.node_id in endpoints for n in rds_nodes)


def test_repair_wires_rds_only():
    builder = GraphBuilder("db-cred-repair")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:bastion",
        props={"name": "bastion"},
    )
    mat = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="material:generic_credential_file:deadbeefdeadbeef",
        props={
            "native_kind": "PivotMaterial",
            "material_kind": "generic_credential_file",
            "locator": "main.tf:138",
            "name_hints": ["RDS_CREDS", "aws-goat-db", "ecs-task-role"],
            "display_name": "Hardcoded password in main.tf:138 → aws-goat-db",
            "source": "collector-enrichment",
            "evidence": {"file": "main.tf", "line": 138, "match": 'password = "***"'},
        },
    )
    # Stale wrong unlocks from earlier buggy imports.
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:RDS_CREDS",
        props={"resource_type": "Secret", "name": "RDS_CREDS"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={"native_kind": "Role", "name": "ecs-task-role"},
    )
    builder.add_edge(src_id=host, rel_type="HAS_MATERIAL", dst_id=mat, props={})
    builder.add_edge(src_id=mat, rel_type="UNLOCKS", dst_id=secret, props={})
    builder.add_edge(src_id=mat, rel_type="UNLOCKS", dst_id=role, props={})

    stats = repair_credential_impact(builder)
    assert stats["pruned"] >= 2
    unlock_dsts = {e.dst_id for e in builder.snapshot.edges if e.rel_type == "UNLOCKS"}
    assert any("aws-goat-db" in d or "RDSInstance" in d for d in unlock_dsts)
    assert secret not in unlock_dsts
    assert role not in unlock_dsts
