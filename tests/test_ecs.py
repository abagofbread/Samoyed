"""ECS topology + escape surface unit tests."""

from __future__ import annotations

from samoyed.cloud.concepts import ConceptType
from samoyed.enumerators.aws.ecs import (
    analyze_ecs_container_definition,
    analyze_ecs_task_definition,
    workload_native_id,
)
from samoyed.graph.builder import GraphBuilder
from samoyed.ingest.concept_normalizer import ConceptNormalizer
from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge
from samoyed.cloud.concepts import CloudProvider, ConfidenceType
from samoyed.path_engine.search import find_attack_paths


GOAT_TASK_DEF = {
    "taskRoleArn": "arn:aws:iam::859695290971:role/ecs-task-role",
    "executionRoleArn": "arn:aws:iam::859695290971:role/ecs-task-execution-role",
    "containerDefinitions": [
        {
            "name": "payroll",
            "image": "859695290971.dkr.ecr.us-east-1.amazonaws.com/goat:latest",
            "privileged": False,
            "linuxParameters": {"capabilities": {"add": ["SYS_PTRACE"]}},
        }
    ],
}


def test_analyze_ecs_sys_ptrace_and_container_creds():
    findings = analyze_ecs_task_definition(GOAT_TASK_DEF, scope_key="task/abc")
    kinds = {f["kind"] for f in findings}
    assert "capabilities" in kinds
    assert "container-credentials" in kinds
    caps = next(f for f in findings if f["kind"] == "capabilities")
    assert "SYS_PTRACE" in caps["description"]
    assert caps["severity"] == "high"


def test_analyze_ecs_privileged_and_docker_sock():
    td = {
        "taskRoleArn": "arn:aws:iam::1:role/task",
        "volumes": [{"name": "dockersock", "host": {"sourcePath": "/var/run/docker.sock"}}],
        "containerDefinitions": [
            {
                "name": "breakout",
                "privileged": True,
                "mountPoints": [
                    {"sourceVolume": "dockersock", "containerPath": "/var/run/docker.sock"}
                ],
            }
        ],
    }
    findings = analyze_ecs_task_definition(td, scope_key="task/evil")
    kinds = {f["kind"] for f in findings}
    assert "privileged" in kinds
    assert "docker-socket" in kinds
    assert "container-credentials" in kinds


def test_analyze_ecs_host_pid_mode():
    findings = analyze_ecs_task_definition(
        {"pidMode": "host", "containerDefinitions": [{"name": "c"}]},
        scope_key="t1",
    )
    assert any(f["kind"] == "hostPID" for f in findings)


def test_analyze_container_dangerous_cap_variants():
    findings = analyze_ecs_container_definition(
        {"name": "c", "linuxParameters": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}}},
        scope_key="t1",
    )
    assert findings and findings[0]["kind"] == "capabilities"


def test_ecs_goat_path_workload_to_instance_role():
    """Compromised ECS container → ptrace escape → host EC2 → instance role."""
    builder = GraphBuilder(session_id="ecs-goat-test")
    task_arn = "arn:aws:ecs:us-east-1:859695290971:task/goat/abc"
    wl_id = workload_native_id(task_arn, "payroll")
    host_id = "EC2Instance:i-0goat"
    task_role = "arn:aws:iam::859695290971:role/ecs-task-role"
    instance_role = "arn:aws:iam::859695290971:role/ecs-instance-role"

    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=task_role,
            scope_id="aws:859695290971",
            properties={"arn": task_role, "name": "ecs-task-role", "resource_type": "Role"},
        ),
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=instance_role,
            scope_id="aws:859695290971",
            properties={"arn": instance_role, "name": "ecs-instance-role", "resource_type": "Role"},
        ),
        ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id=host_id,
            scope_id="aws:859695290971",
            properties={"resource_type": "EC2Instance", "instance_id": "i-0goat"},
            edges=[
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=instance_role,
                    target_concept_type=ConceptType.IDENTITY,
                    props={"role_arn": instance_role},
                )
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id=f"ECSTask:{task_arn}",
            scope_id="aws:859695290971",
            properties={"resource_type": "ECSTask", "task_arn": task_arn, "task_role_arn": task_role},
            edges=[
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=task_role,
                    target_concept_type=ConceptType.IDENTITY,
                    props={"role_kind": "task"},
                ),
                ConceptEdge(
                    rel_type="RUNS_ON",
                    target_native_id=host_id,
                    target_concept_type=ConceptType.RUNTIME_BINDING,
                ),
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.WORKLOAD,
            provider=CloudProvider.AWS,
            native_id=wl_id,
            scope_id="aws:859695290971",
            properties={
                "resource_type": "ECSContainer",
                "native_kind": "ECSContainer",
                "container_name": "payroll",
                "task_arn": task_arn,
            },
            edges=[
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=task_role,
                    target_concept_type=ConceptType.IDENTITY,
                ),
                ConceptEdge(
                    rel_type="RUNS_ON",
                    target_native_id=host_id,
                    target_concept_type=ConceptType.RUNTIME_BINDING,
                ),
                # SYS_PTRACE escape is a transitive edge straight to the host.
                ConceptEdge(
                    rel_type="CAN_ESCAPE_TO",
                    target_native_id=host_id,
                    target_concept_type=ConceptType.RUNTIME_BINDING,
                    props={"mechanism": "capabilities", "severity": "high"},
                    confidence=ConfidenceType.EXPLICIT,
                ),
            ],
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    snapshot = builder.snapshot

    wl_node = next(n for n in snapshot.nodes.values() if n.props.get("native_id") == wl_id)
    inst_node = next(
        n for n in snapshot.nodes.values() if n.props.get("native_id") == instance_role
    )

    paths = find_attack_paths(
        snapshot,
        start_node_id=wl_node.node_id,
        end_node_id=inst_node.node_id,
        max_depth=6,
    )
    assert paths, "expected path from ECS workload to instance role via escape"
    rels = [s.rel_type for s in paths[0].steps]
    assert "CAN_ESCAPE_TO" in rels
    assert "EXECUTES_AS" in rels


def test_ecs_imds_enrichment_skips_task_uses_host():
    from samoyed.attack.surface import enrich_attack_surface

    builder = GraphBuilder(session_id="ecs-imds-skip")
    task_role = "arn:aws:iam::1:role/task"
    inst_role = "arn:aws:iam::1:role/instance"
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=task_role,
            scope_id="aws:1",
            properties={"arn": task_role},
        ),
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=inst_role,
            scope_id="aws:1",
            properties={"arn": inst_role},
        ),
        ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id="ECSTask:arn:aws:ecs:us-east-1:1:task/c/t",
            scope_id="aws:1",
            properties={"resource_type": "ECSTask"},
            edges=[
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=task_role,
                    target_concept_type=ConceptType.IDENTITY,
                )
            ],
        ),
        ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id="EC2Instance:i-abc",
            scope_id="aws:1",
            properties={"resource_type": "EC2Instance", "instance_id": "i-abc"},
            edges=[
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=inst_role,
                    target_concept_type=ConceptType.IDENTITY,
                )
            ],
        ),
    ]
    ConceptNormalizer().ingest(builder, artifacts)
    enrich_attack_surface(builder)
    graph = builder.snapshot

    def _node(native_id: str) -> str:
        return next(
            nid for nid, n in graph.nodes.items() if n.props.get("native_id") == native_id
        )

    ec2_id = _node("EC2Instance:i-abc")
    task_id = _node("ECSTask:arn:aws:ecs:us-east-1:1:task/c/t")

    imds_edges = [
        e
        for e in graph.edges
        if e.rel_type == "CAN_ESCAPE_TO" and e.props.get("mechanism") == "imds"
    ]
    # IMDS credential theft is a direct compute->role edge; only the EC2 host gets
    # one (the ECS task's identity comes from 169.254.170.2, not classic IMDS).
    assert any(e.src_id == ec2_id for e in imds_edges)
    assert not any(e.src_id == task_id for e in imds_edges)
