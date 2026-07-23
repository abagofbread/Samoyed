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


def test_impact_uses_typed_targets_not_name_hints():
    from samoyed.enrichment.impact import impact_targets_for_material

    # Untyped hints alone never unlock — avoid projecting RDSInstance:RDS_CREDS.
    assert impact_targets_for_material(
        kind="generic_credential_file",
        name_hints=["RDS_CREDS", "aws-goat-db", "ecs-task-role"],
    ) == []

    targets = impact_targets_for_material(
        kind="generic_credential_file",
        name_hints=["RDS_CREDS", "aws-goat-db"],
        impact_targets=[{"name": "aws-goat-db", "kind": "db_instance"}],
    )
    assert targets == [{"name": "aws-goat-db", "kind": "db_instance"}]

    # declared_resources are not auto-scanned — collectors must emit impact_targets.
    assert (
        impact_targets_for_material(
            kind="generic_credential_file",
            name_hints=["RDS_CREDS"],
            declared_resources=[
                {"kind": "db_instance", "name": "aws-goat-db"},
                {"kind": "secretsmanager_secret", "name": "RDS_CREDS"},
            ],
        )
        == []
    )

    # Unknown kinds ignored.
    assert impact_targets_for_material(
        impact_targets=[{"name": "x", "kind": "not_a_real_kind"}]
    ) == []


def test_s3_bucket_typed_impact_unlocks_and_blasts():
    from samoyed.enrichment.impact import wire_credential_impact

    builder = GraphBuilder("s3-cred-impact")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:bastion",
        props={"resource_type": "EC2Instance", "name": "bastion"},
    )
    mat = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="material:generic_credential_file:s3deadbeef",
        props={
            "native_kind": "PivotMaterial",
            "material_kind": "generic_credential_file",
            "locator": "main.tf:10",
            "impact_targets": [{"name": "bucket_tf_files", "kind": "s3_bucket"}],
        },
    )
    builder.add_edge(src_id=host, rel_type="HAS_MATERIAL", dst_id=mat, props={})
    stats = wire_credential_impact(
        builder,
        builder.snapshot,
        material_node_id=mat,
        material_kind="generic_credential_file",
        locator="main.tf:10",
        impact_targets=[{"name": "bucket_tf_files", "kind": "s3_bucket"}],
    )
    assert stats["unlocks_applied"] >= 1
    assert stats["projected"] >= 1
    buckets = [
        n
        for n in builder.snapshot.nodes.values()
        if n.props.get("resource_type") == "S3Bucket"
        and n.props.get("bucket_name") == "bucket_tf_files"
    ]
    assert buckets
    unlock_dsts = {e.dst_id for e in builder.snapshot.edges if e.rel_type == "UNLOCKS"}
    assert buckets[0].node_id in unlock_dsts

    blast = get_blast_radius(builder.snapshot, start_node_id=host, max_depth=4, max_paths=20)
    assert buckets[0].node_id in {p.node_ids[-1] for p in blast}


def test_no_unlock_without_impact_targets_despite_declared_resources():
    from samoyed.enrichment.impact import wire_credential_impact

    builder = GraphBuilder("no-declared-sweep")
    mat = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="material:generic_credential_file:nosweep",
        props={"native_kind": "PivotMaterial", "material_kind": "generic_credential_file"},
    )
    stats = wire_credential_impact(
        builder,
        builder.snapshot,
        material_node_id=mat,
        material_kind="generic_credential_file",
        locator="main.tf:1",
        name_hints=["aws-goat-db"],
        declared_resources=[{"kind": "db_instance", "name": "aws-goat-db"}],
    )
    assert stats["unlocks_applied"] == 0
    assert stats["projected"] == 0
    assert not any(e.rel_type == "UNLOCKS" for e in builder.snapshot.edges)


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
    # RDS may be projected by declared_resources inventory or by UNLOCKS impact.
    assert stats["stores_projected"] + stats.get("declared_projected", 0) >= 1
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
            "impact_targets": [{"name": "aws-goat-db", "kind": "db_instance"}],
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


def test_secret_star_unlocks_rds_with_where_vault():
    """Secret:* -[UNLOCKS]-> aws-goat-db with where=RDS_CREDS for blast from CONTROLS."""
    from samoyed.attack.surface import repair_blast_graph
    from samoyed.enrichment.impact import repair_credential_impact

    builder = GraphBuilder("secret-star-unlocks-rds")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::859695290971:role/ecs-instance-role",
        props={"native_kind": "Role", "concept_type": "Identity", "name": "ecs-instance-role"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:*",
        props={"resource_type": "Secret", "native_id": "Secret:*"},
    )
    vault = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS",
        props={
            "resource_type": "Secret",
            "name": "RDS_CREDS",
            "display_name": "RDS_CREDS",
            "arn": "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS",
        },
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
    mat = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="material:generic_credential_file:goatpass",
        props={
            "native_kind": "PivotMaterial",
            "material_kind": "generic_credential_file",
            "locator": "main.tf:138",
            "name_hints": ["RDS_CREDS", "aws-goat-db"],
            "impact_targets": [{"name": "aws-goat-db", "kind": "db_instance"}],
        },
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=stub,
        props={"action": "secretsmanager:*", "resource": "*", "resource_type": "Secret"},
    )
    builder.add_edge(src_id=mat, rel_type="UNLOCKS", dst_id=rds, props={"match": "credential-impact"})

    stats = repair_credential_impact(builder)
    assert stats.get("secret_scope_unlocks", 0) >= 1

    stub_unlocks = [
        e
        for e in builder.snapshot.edges
        if e.src_id == stub and e.dst_id == rds and e.rel_type == "UNLOCKS"
    ]
    assert stub_unlocks, "Secret:* must UNLOCKS aws-goat-db"
    assert stub_unlocks[0].props.get("where") == "RDS_CREDS"
    assert stub_unlocks[0].props.get("via_secret") == "RDS_CREDS"

    vault_unlocks = [
        e
        for e in builder.snapshot.edges
        if e.src_id == vault and e.dst_id == rds and e.rel_type == "UNLOCKS"
    ]
    assert vault_unlocks, "inventored RDS_CREDS must also UNLOCKS aws-goat-db"

    repair_blast_graph(builder)
    paths = get_blast_radius(builder.snapshot, start_node_id=role, max_depth=4, max_paths=20)
    ends = {p.node_ids[-1] for p in paths}
    assert rds in ends, f"expected aws-goat-db in blast from instance role, got {ends}"
    via_secret_star = [
        p
        for p in paths
        if p.node_ids[-1] == rds and stub in p.node_ids
    ]
    assert via_secret_star, "blast path should traverse Secret:* → aws-goat-db"
    assert via_secret_star[0].steps[-1].rel_type == "UNLOCKS"
    assert via_secret_star[0].steps[-1].evidence.get("where") == "RDS_CREDS"
    builder = GraphBuilder("ec2-mat-rds-blast")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:bastion",
        props={"resource_type": "EC2Instance", "name": "bastion", "display_name": "bastion"},
    )
    mat = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="material:generic_credential_file:abcd1234abcd1234",
        props={
            "native_kind": "PivotMaterial",
            "material_kind": "generic_credential_file",
            "locator": "main.tf:138",
            "finding": "Hardcoded password",
            "name_hints": ["RDS_CREDS", "aws-goat-db"],
            "display_name": "Hardcoded password → aws-goat-db",
            "source": "collector-enrichment",
            "evidence": {"file": "main.tf", "line": 138, "match": 'password = "***"'},
        },
    )
    rds = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="RDSInstance:aws-goat-db",
        props={
            "resource_type": "RDSInstance",
            "name": "aws-goat-db",
            "display_name": "aws-goat-db",
            "db_instance_identifier": "aws-goat-db",
            "is_high_value": True,
        },
    )
    builder.add_edge(src_id=host, rel_type="HAS_MATERIAL", dst_id=mat, props={})
    builder.add_edge(
        src_id=mat,
        rel_type="UNLOCKS",
        dst_id=rds,
        props={"match": "credential-impact", "store_kind": "db_instance"},
    )

    blast = get_blast_radius(builder.snapshot, start_node_id=host, max_depth=4, max_paths=20)
    endpoints = [p.node_ids[-1] for p in blast]
    assert rds in endpoints, f"expected named RDS in blast, got {endpoints}"

    rds_path = next(p for p in blast if p.node_ids[-1] == rds)
    rels = [s.rel_type for s in rds_path.steps]
    assert "HAS_MATERIAL" in rels
    assert "UNLOCKS" in rels
    assert rds_path.steps[-1].rel_type == "UNLOCKS"
    # Named RDS unlock should outrank the material leaf when both appear.
    if mat in endpoints:
        assert endpoints.index(rds) < endpoints.index(mat)