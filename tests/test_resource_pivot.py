"""Resource scope intersection + FEEDS pivot tests."""

from __future__ import annotations

from samoyed.attack.surface import enrich_attack_surface
from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.resource_scope import (
    intersect_scopes,
    parse_ecr_image_uri,
    resolve_policy_resource,
)
from samoyed.ingest.concept_normalizer import ConceptNormalizer
from samoyed.path_engine.search import find_attack_paths


def test_service_wildcard_does_not_cross_types():
    """Logs:* must not FEEDS-match Ec2:* (IAM service wildcards)."""
    _, logs = resolve_policy_resource("*", "Logs")
    _, ec2 = resolve_policy_resource("*", "Ec2")
    assert logs.canonical_id.endswith(":*")
    assert ec2.canonical_id.endswith(":*")
    assert intersect_scopes(logs, ec2) is None


def test_rds_star_intersects_inventored_instance():
    _, star = resolve_policy_resource("*", "Rds")
    _, invent = resolve_policy_resource("RDSInstance:aws-goat-db", "RDSInstance")
    # Typed native form
    from samoyed.graph.resource_scope import scope_from_native_id

    invent2 = scope_from_native_id("RDSInstance:aws-goat-db")
    assert invent2 is not None
    hit = intersect_scopes(star, invent2)
    assert hit is not None
    assert hit.match_kind == "type_wildcard"
    assert hit.scope.canonical_id == "RDSInstance:aws-goat-db"

def test_same_type_wildcard_still_matches():
    _, star = resolve_policy_resource("*", "Secret")
    _, named = resolve_policy_resource(
        "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS-AbCdEf",
        "Secret",
    )
    hit = intersect_scopes(star, named)
    assert hit is not None
    assert hit.match_kind == "type_wildcard"


def test_s3_prefix_intersection():
    _nid, writer = resolve_policy_resource("arn:aws:s3:::artifacts/build/*", "S3Bucket")
    _nid2, consumer = resolve_policy_resource("arn:aws:s3:::artifacts/build/prod/*", "S3Bucket")
    hit = intersect_scopes(writer, consumer)
    assert hit is not None
    assert hit.match_kind == "prefix"
    assert hit.scope.path_prefix == "build/prod/"


def test_s3_disjoint_prefixes():
    _, a = resolve_policy_resource("arn:aws:s3:::artifacts/dev/*", "S3Bucket")
    _, b = resolve_policy_resource("arn:aws:s3:::artifacts/prod/*", "S3Bucket")
    assert intersect_scopes(a, b) is None


def test_secret_name_suffix_match():
    _, policy = resolve_policy_resource(
        "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS*",
        "Secret",
    )
    _, invent = resolve_policy_resource(
        "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS-AbCdEf",
        "Secret",
    )
    hit = intersect_scopes(policy, invent)
    assert hit is not None
    assert hit.match_kind in {"arn_match", "exact"}


def test_ecr_image_uri_intersects_repo_arn():
    image = parse_ecr_image_uri(
        "859695290971.dkr.ecr.us-east-1.amazonaws.com/goat:latest"
    )
    assert image is not None
    _, writer = resolve_policy_resource(
        "arn:aws:ecr:us-east-1:859695290971:repository/goat",
        "ECRRepository",
    )
    hit = intersect_scopes(writer, image)
    assert hit is not None
    assert hit.scope.image_tag == "latest"


def test_ecr_tag_mismatch_is_disjoint():
    image = parse_ecr_image_uri(
        "111111111111.dkr.ecr.us-east-1.amazonaws.com/app:v1"
    )
    writer = parse_ecr_image_uri(
        "111111111111.dkr.ecr.us-east-1.amazonaws.com/app:v2"
    )
    assert image and writer
    # Treat writer as repo-level (no tag) vs tagged consumer — should intersect
    _, repo = resolve_policy_resource(
        "arn:aws:ecr:us-east-1:111111111111:repository/app",
        "ECRRepository",
    )
    assert intersect_scopes(repo, image) is not None
    assert intersect_scopes(writer, image) is None


def test_identity_iam_reads_do_not_feeds_mesh():
    """IAM Principal READS of overlapping resources must not FEEDS principal→principal."""
    builder = GraphBuilder(session_id="feeds-no-identity-mesh")
    apigw = (
        "arn:aws:iam::1:role/aws-service-role/ops.apigateway.amazonaws.com/"
        "AWSServiceRoleForAPIGateway"
    )
    app = "arn:aws:iam::1:role/app"
    secret = "Secret:arn:aws:secretsmanager:us-east-1:1:secret:shared-AbCdEf"
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=apigw,
            scope_id="aws:1",
            properties={"arn": apigw},
            edges=[
                ConceptEdge(
                    rel_type="WRITES",
                    target_native_id="Resource:Logs:*",
                    target_concept_type=ConceptType.DATA_STORE,
                    props={"resource": "*", "resource_type": "Logs", "action": "logs:CreateLogGroup"},
                ),
                ConceptEdge(
                    rel_type="WRITES",
                    target_native_id=secret,
                    target_concept_type=ConceptType.SECRET_STORE,
                    props={
                        "resource": "arn:aws:secretsmanager:us-east-1:1:secret:shared*",
                        "resource_type": "Secret",
                        "action": "secretsmanager:PutSecretValue",
                    },
                ),
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=app,
            scope_id="aws:1",
            properties={"arn": app},
            edges=[
                ConceptEdge(
                    rel_type="READS",
                    target_native_id="Resource:Logs:*",
                    target_concept_type=ConceptType.DATA_STORE,
                    props={"resource": "*", "resource_type": "Logs"},
                ),
                ConceptEdge(
                    rel_type="READS",
                    target_native_id=secret,
                    target_concept_type=ConceptType.SECRET_STORE,
                    props={
                        "resource": "arn:aws:secretsmanager:us-east-1:1:secret:shared*",
                        "resource_type": "Secret",
                    },
                ),
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.SECRET_STORE,
            provider=CloudProvider.AWS,
            native_id=secret,
            scope_id="aws:1",
            properties={"resource_type": "Secret"},
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    stats = enrich_attack_surface(builder)
    feeds = [e for e in builder.snapshot.edges if e.rel_type == "FEEDS"]
    assert stats.get("feeds_edges", 0) == 0
    assert feeds == []


def test_feeds_pivot_secret_poison_path():
    builder = GraphBuilder(session_id="feeds-secret")
    writer = "arn:aws:iam::1:role/attacker"
    reader_wl = "ECSContainer:task/payroll"
    secret = "Secret:arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS-AbCdEf"
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=writer,
            scope_id="aws:1",
            properties={"arn": writer},
            edges=[
                ConceptEdge(
                    rel_type="WRITES",
                    target_native_id=secret,
                    target_concept_type=ConceptType.SECRET_STORE,
                    props={
                        "action": "secretsmanager:PutSecretValue",
                        "resource": "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS*",
                        "resource_type": "Secret",
                    },
                )
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.SECRET_STORE,
            provider=CloudProvider.AWS,
            native_id=secret,
            scope_id="aws:1",
            properties={"resource_type": "Secret", "name": "RDS_CREDS"},
        ),
        ConceptArtifact(
            concept_type=ConceptType.WORKLOAD,
            provider=CloudProvider.AWS,
            native_id=reader_wl,
            scope_id="aws:1",
            properties={"resource_type": "ECSContainer", "native_kind": "ECSContainer"},
            edges=[
                ConceptEdge(
                    rel_type="READS",
                    target_native_id=secret,
                    target_concept_type=ConceptType.SECRET_STORE,
                    props={
                        "resource": secret.split(":", 1)[-1],
                        "resource_type": "Secret",
                        "source": "ecs-task-def",
                    },
                )
            ],
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    stats = enrich_attack_surface(builder)
    assert stats.get("feeds_edges", 0) >= 1

    writer_node = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == writer)
    wl_node = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == reader_wl)
    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=writer_node.node_id,
        end_node_id=wl_node.node_id,
        max_depth=4,
    )
    assert paths
    assert any(s.rel_type == "FEEDS" for s in paths[0].steps)
    feeds = next(e for e in builder.snapshot.edges if e.rel_type == "FEEDS")
    assert feeds.props.get("match_kind") in {"arn_match", "exact"}
    assert "RDS_CREDS" in str(feeds.props.get("scope_intersection", ""))


def test_feeds_pivot_ecr_image_poison():
    builder = GraphBuilder(session_id="feeds-ecr")
    writer = "arn:aws:iam::859695290971:role/pusher"
    wl = "ECSContainer:task/app"
    image = "859695290971.dkr.ecr.us-east-1.amazonaws.com/goat:latest"
    ecr = "ECRRepository:arn:aws:ecr:us-east-1:859695290971:repository/goat"
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=writer,
            scope_id="aws:859695290971",
            properties={"arn": writer},
            edges=[
                ConceptEdge(
                    rel_type="WRITES",
                    target_native_id=ecr,
                    target_concept_type=ConceptType.REGISTRY_STORE,
                    props={
                        "action": "ecr:PutImage",
                        "resource": "arn:aws:ecr:us-east-1:859695290971:repository/goat",
                        "resource_type": "ECRRepository",
                    },
                )
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.WORKLOAD,
            provider=CloudProvider.AWS,
            native_id=wl,
            scope_id="aws:859695290971",
            properties={"resource_type": "ECSContainer"},
            edges=[
                ConceptEdge(
                    rel_type="USES_IMAGE",
                    target_native_id=f"aws:ecs:image:{image}",
                    target_concept_type=ConceptType.IMAGE_PROVENANCE,
                    props={"image": image},
                ),
                ConceptEdge(
                    rel_type="PULLS_FROM",
                    src_native_id=f"aws:ecs:image:{image}",
                    target_native_id=ecr,
                    target_concept_type=ConceptType.REGISTRY_STORE,
                    props={"image": image, "resource": ecr.split(":", 1)[-1], "resource_type": "ECRRepository"},
                ),
            ],
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    stats = enrich_attack_surface(builder)
    assert stats.get("feeds_edges", 0) >= 1

    writer_node = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == writer)
    wl_node = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == wl)
    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=writer_node.node_id,
        end_node_id=wl_node.node_id,
        max_depth=4,
    )
    assert paths
    assert "FEEDS" in [s.rel_type for s in paths[0].steps]


def test_rds_control_feeds_workload_that_depends_on_db():
    """Principal CONTROLS inventored RDS + workload DEPENDS_ON same DB → FEEDS."""
    from samoyed.attack.resource_pivot import enrich_resource_pivots

    builder = GraphBuilder("feeds-rds")
    dba = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/dba",
        props={"native_kind": "Role", "concept_type": "Identity"},
    )
    rds = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="RDSInstance:aws-goat-db",
        props={
            "resource_type": "RDSInstance",
            "db_instance_identifier": "aws-goat-db",
            "name": "aws-goat-db",
        },
    )
    app = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="ECSTask:app",
        props={"resource_type": "ECSTask", "concept_type": "Workload", "name": "app"},
    )
    builder.add_edge(
        src_id=dba,
        rel_type="CONTROLS",
        dst_id=rds,
        props={"action": "rds:ModifyDBInstance", "resource_type": "RDSInstance"},
    )
    builder.add_edge(
        src_id=app,
        rel_type="DEPENDS_ON",
        dst_id=rds,
        props={"resource_type": "RDSInstance", "resource": "RDSInstance:aws-goat-db"},
    )
    stats = enrich_resource_pivots(builder)
    assert stats["feeds_edges"] >= 1
    feeds = [
        e
        for e in builder.snapshot.edges
        if e.rel_type == "FEEDS" and e.src_id == dba and e.dst_id == app
    ]
    assert feeds
    assert feeds[0].props.get("family") == "rds"


def test_secret_star_controls_feeds_workload_reading_concrete_secret():
    """Identity CONTROLS Secret:* + Workload READS inventored secret → FEEDS."""
    from samoyed.attack.resource_pivot import enrich_resource_pivots

    builder = GraphBuilder("feeds-secret-star")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={"native_kind": "Role", "concept_type": "Identity"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:*",
        props={"resource_type": "Secret", "native_id": "Secret:*"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS",
        props={
            "resource_type": "Secret",
            "name": "RDS_CREDS",
            "arn": "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS",
        },
    )
    task = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="ECSTask:app",
        props={"resource_type": "ECSTask", "concept_type": "Workload", "name": "app"},
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=stub,
        props={"action": "secretsmanager:*", "resource": "*", "resource_type": "Secret"},
    )
    builder.add_edge(
        src_id=task,
        rel_type="READS",
        dst_id=secret,
        props={
            "resource_type": "Secret",
            "resource": "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS",
        },
    )
    stats = enrich_resource_pivots(builder)
    assert stats["feeds_edges"] >= 1
    feeds = [
        e
        for e in builder.snapshot.edges
        if e.rel_type == "FEEDS" and e.src_id == role and e.dst_id == task
    ]
    assert feeds
    assert feeds[0].props.get("family") == "secretsmanager"
