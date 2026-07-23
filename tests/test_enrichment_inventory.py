"""Declared-resource inventory projection for ECS goat topology."""

from __future__ import annotations

from pathlib import Path

from samoyed.cloud.concepts import ConceptType
from samoyed.collectors.correlate import extract_terraform_names
from samoyed.enrichment.apply import apply_enrichment_report
from samoyed.enrichment.inventory import preferred_enrichment_host, project_declared_inventory
from samoyed.graph.builder import GraphBuilder


def _goat_declared() -> list[dict[str, str]]:
    return [
        {"kind": "db_instance", "name": "aws-goat-db", "tf_address": "aws_db_instance.database-instance"},
        {"kind": "iam_role", "name": "ecs-instance-role", "tf_address": "aws_iam_role.ecs-instance-role"},
        {"kind": "iam_role", "name": "ecs-task-role", "tf_address": "aws_iam_role.ecs-task-role"},
        {"kind": "ecs_cluster", "name": "ecs-lab-cluster", "tf_address": "aws_ecs_cluster.cluster"},
        {
            "kind": "ecs_task_definition",
            "name": "ECS-Lab-Task-definition",
            "tf_address": "aws_ecs_task_definition.task_definition",
        },
        {"kind": "ecs_service", "name": "ecs_service_worker", "tf_address": "aws_ecs_service.worker"},
        {"kind": "secretsmanager_secret", "name": "RDS_CREDS", "tf_address": "aws_secretsmanager_secret.rds_creds"},
        {"kind": "ec2_asg", "name": "ECS-lab-asg", "tf_address": "aws_autoscaling_group.ecs_asg"},
    ]


def _goat_or_fixture(tmp_path: Path) -> Path:
    goat = Path(__file__).resolve().parents[1] / ".samoyed" / "AWSGoat" / "modules" / "module-2"
    if goat.is_dir() and (goat / "resources" / "ecs" / "task_definition.json").is_file():
        return goat
    (tmp_path / "resources" / "ecs").mkdir(parents=True)
    (tmp_path / "resources" / "ecs" / "task_definition.json").write_text(
        '[{"name": "aws-goat-m2", "image": "goat:latest", '
        '"linuxParameters": {"capabilities": {"add": ["SYS_PTRACE"]}}, '
        '"mountPoints": [{"sourceVolume": "modules", "containerPath": "/lib/modules"}]}]',
        encoding="utf-8",
    )
    (tmp_path / "main.tf").write_text(
        'resource "aws_ecs_task_definition" "td" {\n'
        '  pid_mode = "host"\n'
        '  volume {\n    name = "modules"\n    host_path = "/lib/modules"\n  }\n}\n',
        encoding="utf-8",
    )
    return tmp_path


def test_extract_asg_from_terraform():
    text = '''
resource "aws_autoscaling_group" "ecs_asg" {
  name = "ECS-lab-asg"
  desired_capacity = 1
}
'''
    found = extract_terraform_names(text, source_path="main.tf")
    assert any(r["kind"] == "ec2_asg" and r["name"] == "ECS-lab-asg" for r in found)


def test_project_declared_ecs_topology(tmp_path: Path):
    source = _goat_or_fixture(tmp_path)
    builder = GraphBuilder("proj-ecs")
    task_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={"name": "ecs-task-role", "resource_type": "Role", "arn": "arn:aws:iam::1:role/ecs-task-role"},
    )
    instance_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={
            "name": "ecs-instance-role",
            "resource_type": "Role",
            "arn": "arn:aws:iam::1:role/ecs-instance-role",
        },
    )

    stats = project_declared_inventory(
        builder,
        declared_resources=_goat_declared(),
        report={"source_root": str(source)},
    )
    assert stats["ecs_workloads"] >= 1
    assert stats["ecs_hosts"] == 1
    assert stats["escape_surfaces"] >= 1

    graph = builder.snapshot
    workloads = [
        n
        for n in graph.nodes.values()
        if n.props.get("resource_type") == "ECSContainer" and n.props.get("projected_reason") == "declared-ecs"
    ]
    assert any(n.props.get("container_name") == "aws-goat-m2" for n in workloads)
    host = preferred_enrichment_host(graph)
    assert host
    assert graph.nodes[host].props.get("concept_type") == "Workload"

    assert any(
        e.rel_type == "EXECUTES_AS" and e.dst_id == task_role
        for e in graph.edges
        if e.src_id in {w.node_id for w in workloads}
    )
    asg_hosts = [n for n in graph.nodes.values() if n.props.get("projected_reason") == "declared-asg"]
    assert len(asg_hosts) == 1
    assert any(
        e.src_id == asg_hosts[0].node_id and e.rel_type == "EXECUTES_AS" and e.dst_id == instance_role
        for e in graph.edges
    )
    # Escapes are transitive edges rooted at the workload (no EscapeSurface node).
    workload_ids = {w.node_id for w in workloads}
    assert any(
        e.rel_type == "CAN_ESCAPE_TO" and e.src_id in workload_ids for e in graph.edges
    )
    assert not any(e.rel_type == "HAS_ESCAPE_SURFACE" for e in graph.edges)


def test_apply_binds_module_hint_to_projected_workload(tmp_path: Path):
    source = _goat_or_fixture(tmp_path)
    builder = GraphBuilder("apply-ecs-bind")
    builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={"name": "ecs-task-role", "resource_type": "Role"},
    )
    builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={"name": "ecs-instance-role", "resource_type": "Role"},
    )

    report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "source_root": str(source),
        "host_hint": "module-2",
        "declared_resources": _goat_declared(),
        "bindings": [
            {
                "target_ref": "module-2",
                "materials": [
                    {
                        "kind": "database_connection_string",
                        "locator": "startup.sh:2",
                        "confidence": "explicit",
                        "evidence": {"match": "password=x"},
                        "impact_targets": [{"name": "aws-goat-db", "kind": "db_instance"}],
                        "name_hints": ["aws-goat-db", "RDS_CREDS"],
                    }
                ],
            }
        ],
    }
    stats = apply_enrichment_report(builder, report)
    assert stats["ecs_workloads"] >= 1
    assert stats["hostless_bindings"] == 0
    assert stats["materials_applied"] >= 1
    assert any(e.rel_type == "HAS_MATERIAL" for e in builder.snapshot.edges)
    assert any(e.rel_type == "UNLOCKS" for e in builder.snapshot.edges)
    host = preferred_enrichment_host(builder.snapshot)
    assert host in stats["hosts_updated"]
