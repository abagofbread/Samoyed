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
