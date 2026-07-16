"""Blast radius should surface capability→resource hits and PassRole→trusted roles."""

from __future__ import annotations

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.attack.high_value import enrich_high_value_targets
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.path_engine.search import get_blast_radius


def test_blast_includes_capability_resources_not_crowded_out_by_privesc():
    builder = GraphBuilder("blast-resources")
    task = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/ecs-task-role", "name": "ecs-task-role"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:*",
        props={"resource_type": "Secret", "native_id": "Secret:*"},
    )
    # Many noisy privesc targets first in adjacency.
    noise = []
    for i in range(25):
        nid = builder.add_concept_node(
            concept_type=ConceptType.IDENTITY,
            native_id=f"arn:aws:iam::1:role/aws-service-role/svc.amazonaws.com/Noise{i}",
            props={
                "native_kind": "Role",
                "arn": f"arn:aws:iam::1:role/aws-service-role/svc.amazonaws.com/Noise{i}",
            },
        )
        noise.append(nid)
        builder.add_edge(
            src_id=task,
            rel_type="CAN_PRIVESC_TO",
            dst_id=nid,
            props={"pattern_id": "aws-lambda-update-configuration-layer", "pattern_name": "Lambda malicious layer"},
        )
    builder.add_edge(
        src_id=task,
        rel_type="CONTROLS",
        dst_id=secret,
        props={"action": "secretsmanager:*", "resource_type": "Secret"},
    )

    paths = get_blast_radius(builder.snapshot, start_node_id=task, max_depth=2, max_paths=15)
    ends = [p.target_match.get("node_id") for p in paths]
    assert secret in ends
    # Resource hit should outrank service-linked noise in the top results.
    secret_idx = ends.index(secret)
    assert secret_idx < 8


def test_passrole_runinstances_targets_ec2_trusting_deployer():
    builder = GraphBuilder("blast-passrole")
    instance = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/ecs-instance-role",
            "name": "ecs-instance-role",
        },
    )
    deployer = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ec2Deployer-role",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/ec2Deployer-role",
            "name": "ec2Deployer-role",
            "is_high_value": True,
            "high_value_kind": "administrator-policy",
        },
    )
    service = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="Service:ec2.amazonaws.com",
        props={"native_kind": "Service", "arn": "ec2.amazonaws.com"},
    )
    builder.add_edge(src_id=service, rel_type="CAN_ASSUME_ROLE", dst_id=deployer, props={})
    # Capability shape: PassRole + RunInstances (and Attach so both patterns fire).
    builder.add_edge(
        src_id=instance,
        rel_type="CONTROLS",
        dst_id=deployer,
        props={"action": "iam:PassRole", "resource_type": "Role"},
    )
    builder.add_edge(
        src_id=instance,
        rel_type="EXECUTES",
        dst_id=builder.add_concept_node(
            concept_type=ConceptType.DATA_STORE,
            native_id="EC2Instance:*",
            props={"resource_type": "EC2Instance"},
        ),
        props={"action": "ec2:RunInstances"},
    )
    builder.add_edge(
        src_id=instance,
        rel_type="CONTROLS",
        dst_id=instance,
        props={"action": "iam:AttachRolePolicy"},
    )
    # Entitlement actions collector reads from edges' action props via collect_principal_actions
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="pol:instance",
        props={
            "principal_arn": "arn:aws:iam::1:role/ecs-instance-role",
            "actions": ["iam:PassRole", "ec2:RunInstances", "iam:AttachRolePolicy", "iam:*"],
        },
    )

    apply_attack_analysis(builder, provider=CloudProvider.AWS)
    enrich_high_value_targets(builder, provider=CloudProvider.AWS)

    passrole_edges = [
        props
        for dst, rel, props in builder.snapshot.adjacency.get(instance, [])
        if rel == "CAN_PRIVESC_TO"
        and dst == deployer
        and "PassRole" in str(props.get("pattern_name") or props.get("pattern_id") or "")
    ]
    assert passrole_edges, "expected EC2 RunInstances (PassRole) → ec2Deployer-role"

    paths = get_blast_radius(builder.snapshot, start_node_id=instance, max_depth=3, max_paths=20)
    ends = {p.target_match.get("node_id") for p in paths}
    assert deployer in ends
    # Prefer PassRole-labeled hop when present
    to_dep = next(p for p in paths if p.target_match.get("node_id") == deployer)
    assert "PassRole" in str(to_dep.steps[-1].evidence.get("pattern_name") or "")
