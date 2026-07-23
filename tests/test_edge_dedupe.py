"""Redundant edge dedupe: assume subsumed by privesc, identical collapse."""

from __future__ import annotations

from samoyed.attack.surface import enrich_attack_surface
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.dedupe import dedupe_redundant_edges


def test_drops_can_assume_when_privesc_exists():
    builder = GraphBuilder("dedupe-assume")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/a",
        props={"native_kind": "User"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/b",
        props={"native_kind": "Role"},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role, props={})
    builder.add_edge(
        src_id=user,
        rel_type="CAN_PRIVESC_TO",
        dst_id=role,
        props={"pattern_id": "aws-ec2-run-instances", "pattern_name": "EC2 RunInstances (PassRole)"},
    )
    stats = dedupe_redundant_edges(builder)
    assert stats["assume_dropped_for_privesc"] == 1
    rels = {(e.src_id, e.rel_type, e.dst_id) for e in builder.snapshot.edges}
    assert (user, "CAN_PRIVESC_TO", role) in rels
    assert (user, "CAN_ASSUME_ROLE", role) not in rels


def test_keeps_assume_when_privesc_is_ufc_not_assume():
    builder = GraphBuilder("dedupe-ufc")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/dev",
        props={"native_kind": "User"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/admin",
        props={"native_kind": "Role"},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role, props={})
    builder.add_edge(
        src_id=user,
        rel_type="CAN_PRIVESC_TO",
        dst_id=role,
        props={"pattern_id": "aws-lambda-update-code", "pattern_name": "Lambda code takeover"},
    )
    stats = dedupe_redundant_edges(builder)
    assert stats["assume_dropped_for_privesc"] == 0
    rels = {e.rel_type for e in builder.snapshot.edges if e.src_id == user and e.dst_id == role}
    assert rels == {"CAN_ASSUME_ROLE", "CAN_PRIVESC_TO"}


def test_collapses_identical_capability_edges():
    builder = GraphBuilder("dedupe-ident")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/r",
        props={"native_kind": "Role"},
    )
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="S3Bucket:x",
        props={"resource_type": "S3Bucket"},
    )
    builder.add_edge(src_id=role, rel_type="READS", dst_id=bucket, props={"action": "s3:GetObject"})
    builder.add_edge(src_id=role, rel_type="READS", dst_id=bucket, props={"action": "s3:ListBucket"})
    builder.add_edge(src_id=role, rel_type="READS", dst_id=bucket, props={"action": "s3:GetObject"})
    stats = dedupe_redundant_edges(builder)
    assert stats["identical_collapsed"] == 2
    reads = [e for e in builder.snapshot.edges if e.rel_type == "READS"]
    assert len(reads) == 1
    assert set(reads[0].props.get("actions") or []) >= {"s3:GetObject", "s3:ListBucket"}


def test_parallel_escape_edges_survive_dedupe():
    """Distinct escape techniques to the same host are parallel edges, not merged."""
    builder = GraphBuilder("dedupe-escape")
    pod = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="kubernetes:pod:default:evil",
        props={"native_kind": "Pod"},
    )
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="kubernetes:node:host:lab",
        props={"resource_type": "NodeHost"},
    )
    for mechanism in ("privileged", "docker-socket", "SYS_PTRACE"):
        builder.add_edge(
            src_id=pod,
            rel_type="CAN_ESCAPE_TO",
            dst_id=host,
            props={"mechanism": mechanism, "severity": "critical"},
        )
    # A true duplicate (same mechanism) should still collapse.
    builder.add_edge(
        src_id=pod,
        rel_type="CAN_ESCAPE_TO",
        dst_id=host,
        props={"mechanism": "privileged", "severity": "critical"},
    )

    dedupe_redundant_edges(builder)
    escape_edges = [
        e
        for e in builder.snapshot.edges
        if e.rel_type == "CAN_ESCAPE_TO" and e.src_id == pod and e.dst_id == host
    ]
    mechanisms = sorted(e.props.get("mechanism") for e in escape_edges)
    assert mechanisms == ["SYS_PTRACE", "docker-socket", "privileged"]


def test_drops_passrole_controls_when_privesc_to_same_identity():
    builder = GraphBuilder("dedupe-passrole")
    src = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/instance",
        props={"native_kind": "Role"},
    )
    deployer = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/deployer",
        props={"native_kind": "Role"},
    )
    builder.add_edge(
        src_id=src,
        rel_type="CONTROLS",
        dst_id=deployer,
        props={"action": "iam:PassRole", "resource_type": "Role"},
    )
    builder.add_edge(
        src_id=src,
        rel_type="CAN_PRIVESC_TO",
        dst_id=deployer,
        props={
            "pattern_id": "aws-ec2-run-instances",
            "pattern_name": "EC2 RunInstances (PassRole)",
        },
    )
    # Broad iam:* CONTROLS should survive
    iam_star = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="IAM:*",
        props={"native_kind": "IAM"},
    )
    builder.add_edge(src_id=src, rel_type="CONTROLS", dst_id=iam_star, props={"action": "iam:*"})

    stats = dedupe_redundant_edges(builder)
    assert stats["identity_capability_dropped_for_privesc"] == 1
    pairs = {(e.rel_type, e.dst_id) for e in builder.snapshot.edges if e.src_id == src}
    assert ("CAN_PRIVESC_TO", deployer) in pairs
    assert ("CONTROLS", deployer) not in pairs
    assert ("CONTROLS", iam_star) in pairs


def test_enrich_attack_surface_runs_dedupe():
    builder = GraphBuilder("dedupe-surface")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/a",
        props={"native_kind": "User", "is_caller": True},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/b",
        props={"native_kind": "Role"},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role)
    builder.add_edge(
        src_id=user,
        rel_type="CAN_PRIVESC_TO",
        dst_id=role,
        props={"pattern_id": "aws-iam-passrole-instance-profile", "pattern_name": "PassRole"},
    )
    stats = enrich_attack_surface(builder, provider=CloudProvider.AWS)
    assert stats.get("assume_dropped_for_privesc", 0) >= 1
