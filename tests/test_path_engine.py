from __future__ import annotations


from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge
from samoyed.cloud.capabilities import map_aws_action
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.ingest.concept_normalizer import ConceptNormalizer
from samoyed.path_engine.custom_query import run_graph_query
from samoyed.path_engine.search import find_attack_paths, find_forward_reachability, get_blast_radius


def test_map_aws_s3_read():
    m = map_aws_action("s3:GetObject")
    assert m is not None
    assert m.capability.value == "READS"


def test_multi_hop_path():
    builder = GraphBuilder("test-session")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/alice",
        props={"is_caller": True},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:role/admin",
        props={"native_kind": "Role"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:123:secret:prod",
        props={"resource_type": "Secret"},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role)
    builder.add_edge(src_id=role, rel_type="READS", dst_id=secret)

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=user,
        target_concept="SecretStore",
        max_depth=4,
    )
    assert len(paths) == 1
    assert paths[0].score > 0
    assert len(paths[0].steps) == 2


def test_attack_paths_default_high_value_target():
    builder = GraphBuilder("test-session")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/alice",
        props={"is_caller": True},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:role/admin",
        props={"native_kind": "Role"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:123:secret:prod",
        props={"resource_type": "Secret", "is_high_value": True},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role)
    builder.add_edge(src_id=role, rel_type="READS", dst_id=secret)

    result = run_graph_query(builder.snapshot, start_node_id=user, mode="paths", max_depth=4)
    assert result["paths"]
    assert any(p["target_match"].get("concept_type") == "SecretStore" for p in result["paths"])


def test_bidirectional_attack_paths_follow_inbound_edges():
    builder = GraphBuilder("test-session")
    admin = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/admin",
        props={"native_kind": "User", "is_high_value": True},
    )
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/alice",
        props={"is_caller": True},
    )
    builder.add_edge(src_id=admin, rel_type="CONTROLS", dst_id=user, props={"action": "iam:AttachUserPolicy"})

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=user,
        target_concept="high_value",
        direction="both",
        max_depth=2,
    )
    assert any(p.node_ids[-1] == admin for p in paths)


def test_forward_blast_radius_reaches_all_outbound_nodes():
    builder = GraphBuilder("test-session")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/alice",
        props={"is_caller": True},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:role/admin",
        props={"native_kind": "Role"},
    )
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="arn:aws:s3:::exports",
        props={"resource_type": "S3Bucket"},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role)
    builder.add_edge(src_id=role, rel_type="READS", dst_id=bucket)

    paths = get_blast_radius(builder.snapshot, start_node_id=user, max_depth=4)
    reached = {p.target_match["node_id"] for p in paths}
    assert role in reached
    assert bucket in reached

    direct = find_forward_reachability(builder.snapshot, start_node_id=user, max_depth=1)
    assert len(direct) == 1
    assert direct[0].node_ids[-1] == role


def test_normalizer_trust_edge():
    builder = GraphBuilder("test-session")
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id="arn:aws:iam::123:user/alice",
            scope_id="aws:account:123",
            properties={"is_caller": True},
        ),
        ConceptArtifact(
            concept_type=ConceptType.TRUST,
            provider=CloudProvider.AWS,
            native_id="trust:1",
            scope_id="aws:account:123",
            edges=[
                ConceptEdge(
                    rel_type="CAN_ASSUME_ROLE",
                    src_native_id="arn:aws:iam::123:user/alice",
                    target_native_id="arn:aws:iam::123:role/admin",
                    target_concept_type=ConceptType.IDENTITY,
                )
            ],
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    assert any(e.rel_type == "CAN_ASSUME_ROLE" for e in builder.snapshot.edges)
