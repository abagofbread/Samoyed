"""Blast radius should surface capability→resource hits and PassRole→trusted roles."""

from __future__ import annotations

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.attack.high_value import enrich_high_value_targets
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.path_engine.search import get_blast_radius


def test_blast_ranks_control_star_above_reads_on_inventored_buckets():
    """Influence story: CONTROLS Secret:* beats READS on random inventored S3."""
    builder = GraphBuilder("blast-influence")
    task = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={"native_kind": "Role", "name": "ecs-task-role"},
    )
    secret_star = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:*",
        props={"resource_type": "Secret", "native_id": "Secret:*"},
    )
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="S3Bucket:awsserverlessrepo-changesets",
        props={"resource_type": "S3Bucket", "bucket_name": "awsserverlessrepo-changesets"},
    )
    outcome = builder.add_concept_node(
        concept_type=ConceptType.ATTACK_OUTCOME,
        native_id="AttackOutcome:aws:administrator-access",
        props={
            "concept_type": "AttackOutcome",
            "display_name": "Administrator access",
            "is_high_value": True,
        },
    )
    builder.add_edge(src_id=task, rel_type="CONTROLS", dst_id=secret_star, props={"action": "secretsmanager:*"})
    builder.add_edge(src_id=task, rel_type="READS", dst_id=bucket, props={"action": "s3:GetObject"})
    builder.add_edge(
        src_id=task,
        rel_type="CAN_PRIVESC_TO",
        dst_id=outcome,
        props={"pattern_id": "aws-admin", "attack_outcome": "administrator-access"},
    )
    # Noise READ stubs that used to fill the blast list
    for noise in ("Ecr:*", "Tag:*", "Docdb-Elastic:*", "Rds:*"):
        nid = builder.add_concept_node(
            concept_type=ConceptType.DATA_STORE,
            native_id=noise,
            props={"resource_type": noise.split(":")[0], "native_id": noise},
        )
        builder.add_edge(src_id=task, rel_type="READS", dst_id=nid, props={"action": "ignored"})

    paths = get_blast_radius(builder.snapshot, start_node_id=task, max_depth=2, max_paths=10)
    ends = [p.target_match.get("node_id") for p in paths]
    assert secret_star in ends
    assert ends.index(secret_star) < ends.index(bucket)
    assert ends.index(secret_star) < ends.index(outcome)
    assert paths[0].target_match.get("blast_label", "").startswith("CONTROLS")


def test_blast_ranks_feeds_poison_high():
    builder = GraphBuilder("blast-feeds")
    writer = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ci",
        props={"native_kind": "Role"},
    )
    consumer = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:prod",
        props={"native_kind": "LambdaFunction", "resource_type": "LambdaFunction"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="Ecr:*",
        props={"native_id": "Ecr:*"},
    )
    builder.add_edge(
        src_id=writer,
        rel_type="FEEDS",
        dst_id=consumer,
        props={"scope_intersection": "S3Bucket:artifacts", "match_kind": "exact"},
    )
    builder.add_edge(src_id=writer, rel_type="READS", dst_id=stub, props={})
    paths = get_blast_radius(builder.snapshot, start_node_id=writer, max_depth=2, max_paths=5)
    assert paths[0].target_match.get("node_id") == consumer
    assert paths[0].steps[-1].rel_type == "FEEDS"


def test_blast_prefers_writes_over_reads_to_same_resource():
    """Same inventored/stub node: WRITES must win over READS (BFS first-edge trap)."""
    builder = GraphBuilder("blast-write-upgrade")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/task",
        props={"native_kind": "Role"},
    )
    lam = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="Lambda:arn:aws:lambda:*:*:function:SecretsManager*",
        props={"native_id": "Lambda:arn:aws:lambda:*:*:function:SecretsManager*", "resource_type": "Lambda"},
    )
    # Adjacency order often lists READS first — blast must still surface WRITES.
    builder.add_edge(src_id=role, rel_type="READS", dst_id=lam, props={"action": "lambda:GetFunction"})
    builder.add_edge(
        src_id=role,
        rel_type="WRITES",
        dst_id=lam,
        props={"action": "lambda:UpdateFunctionConfiguration"},
    )
    paths = get_blast_radius(builder.snapshot, start_node_id=role, max_depth=2, max_paths=5)
    hit = next(p for p in paths if p.target_match.get("node_id") == lam)
    assert hit.steps[-1].rel_type == "WRITES"
    assert hit.target_match.get("impact_tier", 0) >= 70


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


def test_blast_omits_star_stub_when_capability_glob_concrete_exists():
    from samoyed.attack.capability_bindings import enrich_capability_bindings

    builder = GraphBuilder("blast-omit-stub")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/writer",
        props={"native_kind": "Role", "concept_type": "Identity"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:*",
        props={"resource_type": "Secret", "native_id": "Secret:*"},
    )
    concrete = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:app-config",
        props={
            "resource_type": "Secret",
            "name": "app-config",
            "arn": "arn:aws:secretsmanager:us-east-1:1:secret:app-config",
        },
    )
    # Secrets only expand when a workload/runtime actually consumes them.
    workload = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="ecs:task/app",
        props={"concept_type": "Workload"},
    )
    builder.add_edge(src_id=workload, rel_type="READS", dst_id=concrete, props={})
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=stub,
        props={"action": "secretsmanager:*", "resource": "*", "resource_type": "Secret"},
    )
    enrich_capability_bindings(builder)

    paths = get_blast_radius(builder.snapshot, start_node_id=role, max_depth=2, max_paths=10)
    ends = [p.target_match.get("node_id") for p in paths]
    assert concrete in ends
    assert stub not in ends, "Secret:* must be omitted once capability-glob concrete exists"


def test_capability_glob_only_binds_consumed_secrets():
    """Secret:* expands onto inventored secrets with use-side consumers — not unused vaults."""
    from samoyed.attack.capability_bindings import enrich_capability_bindings

    builder = GraphBuilder("skip-unused-secret")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={"native_kind": "Role", "concept_type": "Identity"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:*",
        props={"resource_type": "Secret"},
    )
    unused = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS",
        props={
            "resource_type": "Secret",
            "name": "RDS_CREDS",
            "arn": "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS",
        },
    )
    useful = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:app-config",
        props={"resource_type": "Secret", "name": "app-config"},
    )
    workload = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="ecs:task/app",
        props={"concept_type": "Workload"},
    )
    builder.add_edge(src_id=workload, rel_type="READS", dst_id=useful, props={})
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=stub,
        props={"action": "secretsmanager:*", "resource": "*", "resource_type": "Secret"},
    )
    # Stale capability-glob onto unused vault — must be pruned on re-enrich.
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=unused,
        props={"discovered_via": "capability-glob", "action": "secretsmanager:*"},
    )
    stats = enrich_capability_bindings(builder)
    assert stats.get("unused_secret_bindings_pruned", 0) >= 1
    assert not any(
        e.dst_id == unused and e.props.get("discovered_via") == "capability-glob"
        for e in builder.snapshot.edges
    )
    assert any(
        e.dst_id == useful and e.props.get("discovered_via") == "capability-glob"
        for e in builder.snapshot.edges
        if e.src_id == role and e.rel_type == "CONTROLS"
    )


def test_blast_reaches_inventored_ec2_via_passrole_runinstances():
    """PassRole+RunInstances privesc expands onto inventored EC2 EXECUTES_AS deployer."""
    from samoyed.attack.passrole_ec2 import enrich_passrole_ec2_bindings
    from samoyed.attack.surface import enrich_attack_surface

    builder = GraphBuilder("blast-passrole-ec2")
    instance = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/ecs-instance-role",
            "name": "ecs-instance-role",
            "is_caller": True,
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
    stub = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:*",
        props={"resource_type": "EC2Instance"},
    )
    ec2 = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:i-goat01",
        props={"resource_type": "EC2Instance", "instance_id": "i-goat01", "name": "goat-box"},
    )
    builder.add_edge(src_id=service, rel_type="CAN_ASSUME_ROLE", dst_id=deployer, props={})
    builder.add_edge(src_id=ec2, rel_type="EXECUTES_AS", dst_id=deployer, props={})
    builder.add_edge(
        src_id=instance,
        rel_type="CONTROLS",
        dst_id=deployer,
        props={"action": "iam:PassRole", "resource_type": "Role"},
    )
    builder.add_edge(
        src_id=instance,
        rel_type="EXECUTES",
        dst_id=stub,
        props={"action": "ec2:RunInstances", "resource": "*", "resource_type": "EC2Instance"},
    )
    builder.add_edge(
        src_id=instance,
        rel_type="CONTROLS",
        dst_id=instance,
        props={"action": "iam:AttachRolePolicy"},
    )
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="pol:instance",
        props={
            "principal_arn": "arn:aws:iam::1:role/ecs-instance-role",
            "actions": ["iam:PassRole", "ec2:RunInstances", "iam:AttachRolePolicy", "iam:*"],
        },
    )

    apply_attack_analysis(builder, provider=CloudProvider.AWS)
    enrich_passrole_ec2_bindings(builder)
    enrich_attack_surface(builder, provider=CloudProvider.AWS)

    assert any(
        e.src_id == instance
        and e.dst_id == ec2
        and e.rel_type == "EXECUTES"
        and e.props.get("discovered_via") == "passrole-ec2-inventory"
        for e in builder.snapshot.edges
    )

    paths = get_blast_radius(builder.snapshot, start_node_id=instance, max_depth=4, max_paths=30)
    ends = {p.target_match.get("node_id") for p in paths}
    assert deployer in ends
    assert ec2 in ends
    assert stub not in ends


def test_blast_lazy_repair_wires_s3_glob_feeds_to_consumer():
    """Without prior enrich-surface, repair_blast_graph makes S3:* → bucket → FEEDS → app."""
    from samoyed.attack.surface import repair_blast_graph

    builder = GraphBuilder("blast-lazy-feeds")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/writer",
        props={"native_kind": "Role", "concept_type": "Identity"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="S3Bucket:*",
        props={"resource_type": "S3Bucket", "native_id": "S3Bucket:*"},
    )
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="S3Bucket:prod_bucket",
        props={"resource_type": "S3Bucket", "bucket_name": "prod_bucket", "name": "prod_bucket"},
    )
    app = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="ecs:task/internal_app",
        props={"concept_type": "Workload", "name": "internal_app"},
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=stub,
        props={"action": "s3:*", "resource": "*", "resource_type": "S3Bucket"},
    )
    builder.add_edge(src_id=app, rel_type="READS", dst_id=bucket, props={})

    # No enrich_attack_surface — only lazy blast repair.
    stats = repair_blast_graph(builder)
    assert stats.get("capability_bindings", 0) >= 1
    assert stats.get("feeds_edges", 0) >= 1
    assert any(
        e.src_id == role and e.dst_id == bucket and e.rel_type == "CONTROLS"
        for e in builder.snapshot.edges
    )
    assert any(
        e.src_id == role and e.dst_id == app and e.rel_type == "FEEDS"
        for e in builder.snapshot.edges
    )

    paths = get_blast_radius(builder.snapshot, start_node_id=role, max_depth=3, max_paths=20)
    ends = {p.target_match.get("node_id") for p in paths}
    assert app in ends
    feeds_paths = [p for p in paths if p.steps and p.steps[-1].rel_type == "FEEDS"]
    assert feeds_paths
    assert any(p.node_ids[-1] == app for p in feeds_paths)
