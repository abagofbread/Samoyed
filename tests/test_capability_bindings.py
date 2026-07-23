"""Capability glob → inventored resource bindings for blast impact."""

from __future__ import annotations

from samoyed.attack.capability_bindings import enrich_capability_bindings
from samoyed.attack.surface import enrich_attack_surface
from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.ingest.concept_normalizer import ConceptNormalizer
from samoyed.path_engine.search import get_blast_radius


def test_capability_glob_binds_s3_star_to_inventored_bucket():
    builder = GraphBuilder("glob-s3")
    role = "arn:aws:iam::1:role/writer"
    bucket_name = "prod-artifacts"
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=role,
            scope_id="aws:1",
            properties={"arn": role, "native_kind": "Role"},
            edges=[
                ConceptEdge(
                    rel_type="WRITES",
                    target_native_id="S3Bucket:*",
                    target_concept_type=ConceptType.DATA_STORE,
                    props={
                        "action": "s3:PutObject",
                        "resource": "*",
                        "resource_type": "S3Bucket",
                    },
                )
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.DATA_STORE,
            provider=CloudProvider.AWS,
            native_id=f"S3Bucket:{bucket_name}",
            scope_id="aws:1",
            properties={"resource_type": "S3Bucket", "bucket_name": bucket_name},
        ),
        ConceptArtifact(
            concept_type=ConceptType.DATA_STORE,
            provider=CloudProvider.AWS,
            native_id="S3Bucket:other-account-noise",
            scope_id="aws:1",
            properties={"resource_type": "S3Bucket", "bucket_name": "other-account-noise"},
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    stats = enrich_capability_bindings(builder)
    assert stats["capability_bindings"] >= 2

    role_node = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == role)
    bucket_node = next(
        n for n in builder.snapshot.nodes.values() if n.props.get("bucket_name") == bucket_name
    )
    bound = [
        e
        for e in builder.snapshot.edges
        if e.src_id == role_node.node_id
        and e.dst_id == bucket_node.node_id
        and e.rel_type == "WRITES"
        and e.props.get("discovered_via") == "capability-glob"
    ]
    assert bound, "expected WRITES edge from role to inventored bucket via glob"


def test_blast_prefers_inventored_bucket_over_star_stub():
    builder = GraphBuilder("blast-glob")
    role = "arn:aws:iam::1:role/writer"
    bucket_name = "crown-jewel-bucket"
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=role,
            scope_id="aws:1",
            properties={"arn": role, "native_kind": "Role", "is_caller": True},
            edges=[
                ConceptEdge(
                    rel_type="CONTROLS",
                    target_native_id="S3Bucket:*",
                    target_concept_type=ConceptType.DATA_STORE,
                    props={"action": "s3:*", "resource": "*", "resource_type": "S3Bucket"},
                )
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.DATA_STORE,
            provider=CloudProvider.AWS,
            native_id=f"S3Bucket:{bucket_name}",
            scope_id="aws:1",
            properties={"resource_type": "S3Bucket", "bucket_name": bucket_name},
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    enrich_attack_surface(builder, provider=CloudProvider.AWS)

    role_node = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == role)
    bucket_node = next(
        n for n in builder.snapshot.nodes.values() if n.props.get("bucket_name") == bucket_name
    )
    paths = get_blast_radius(builder.snapshot, start_node_id=role_node.node_id, max_depth=2, max_paths=10)
    ends = [p.target_match.get("node_id") for p in paths]
    assert bucket_node.node_id in ends
    # Concrete inventored bucket should outrank the S3Bucket:* stub when both present.
    star = next(
        (n.node_id for n in builder.snapshot.nodes.values() if n.props.get("native_id") == "S3Bucket:*"),
        None,
    )
    if star and star in ends and bucket_node.node_id in ends:
        assert ends.index(bucket_node.node_id) < ends.index(star)
    # After capability-glob, superseded * stubs are omitted from blast.
    assert star not in ends or ends.index(bucket_node.node_id) == 0


def test_capability_glob_binds_rds_star_to_inventored_instance():
    builder = GraphBuilder("glob-rds")
    role = "arn:aws:iam::1:role/dba"
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=role,
            scope_id="aws:1",
            properties={"arn": role, "native_kind": "Role"},
            edges=[
                ConceptEdge(
                    rel_type="CONTROLS",
                    target_native_id="Rds:*",
                    target_concept_type=ConceptType.DATA_STORE,
                    props={
                        "action": "rds:*",
                        "resource": "*",
                        "resource_type": "Rds",
                    },
                )
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.DATA_STORE,
            provider=CloudProvider.AWS,
            native_id="RDSInstance:aws-goat-db",
            scope_id="aws:1",
            properties={
                "resource_type": "RDSInstance",
                "name": "aws-goat-db",
                "db_instance_identifier": "aws-goat-db",
            },
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    stats = enrich_capability_bindings(builder)
    assert stats["capability_bindings"] >= 1

    role_node = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == role)
    rds_node = next(
        n
        for n in builder.snapshot.nodes.values()
        if n.props.get("db_instance_identifier") == "aws-goat-db"
    )
    bound = [
        e
        for e in builder.snapshot.edges
        if e.src_id == role_node.node_id
        and e.dst_id == rds_node.node_id
        and e.rel_type == "CONTROLS"
        and e.props.get("discovered_via") == "capability-glob"
    ]
    assert bound, "expected CONTROLS from role to inventored RDS via Rds:* glob"

    enrich_attack_surface(builder, provider=CloudProvider.AWS)
    paths = get_blast_radius(builder.snapshot, start_node_id=role_node.node_id, max_depth=2, max_paths=10)
    ends = [p.target_match.get("node_id") for p in paths]
    assert rds_node.node_id in ends
    star = next(
        (n.node_id for n in builder.snapshot.nodes.values() if (n.props.get("native_id") or "").endswith("Rds:*") or n.props.get("native_id") == "Rds:*"),
        None,
    )
    assert star not in ends, "superseded Rds:* stub must be omitted from blast"


def test_capability_glob_binds_ec2_star_to_inventored_instance():
    builder = GraphBuilder("glob-ec2")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/admin",
        props={"native_kind": "Role", "concept_type": "Identity"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:*",
        props={"resource_type": "EC2Instance", "native_id": "EC2Instance:*"},
    )
    ec2 = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:i-abc123",
        props={
            "resource_type": "EC2Instance",
            "instance_id": "i-abc123",
            "name": "bastion",
        },
    )
    builder.add_edge(
        src_id=role,
        rel_type="EXECUTES",
        dst_id=stub,
        props={"action": "ec2:RunInstances", "resource": "*", "resource_type": "EC2Instance"},
    )
    stats = enrich_capability_bindings(builder)
    assert stats["capability_bindings"] >= 1
    bound = [
        e
        for e in builder.snapshot.edges
        if e.src_id == role
        and e.dst_id == ec2
        and e.rel_type == "EXECUTES"
        and e.props.get("discovered_via") == "capability-glob"
    ]
    assert bound
    paths = get_blast_radius(builder.snapshot, start_node_id=role, max_depth=2, max_paths=10)
    ends = [p.target_match.get("node_id") for p in paths]
    assert ec2 in ends
    assert stub not in ends


def test_capability_glob_binds_lambda_secretsmanager_stub():
    builder = GraphBuilder("glob-lambda-sm")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/task",
        props={"native_kind": "Role", "concept_type": "Identity"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="Lambda:arn:aws:lambda:*:*:function:SecretsManager*",
        props={"resource_type": "Lambda"},
    )
    fn = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:SecretsManagerRotation",
        props={"resource_type": "LambdaFunction"},
    )
    other = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:billing",
        props={"resource_type": "LambdaFunction"},
    )
    builder.add_edge(
        src_id=role,
        rel_type="WRITES",
        dst_id=stub,
        props={
            "action": "lambda:UpdateFunctionConfiguration",
            "resource": "arn:aws:lambda:*:*:function:SecretsManager*",
            "resource_type": "LambdaFunction",
        },
    )
    stats = enrich_capability_bindings(builder)
    assert stats["capability_bindings"] >= 1
    assert any(
        e.dst_id == fn and e.props.get("discovered_via") == "capability-glob"
        for e in builder.snapshot.edges
        if e.src_id == role and e.rel_type == "WRITES"
    )
    assert not any(
        e.dst_id == other and e.props.get("discovered_via") == "capability-glob"
        for e in builder.snapshot.edges
        if e.src_id == role
    )
