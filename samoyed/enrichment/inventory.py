"""Project collector ``declared_resources`` into inventored graph nodes.

Static collect knows ECS/ASG/RDS names from Terraform even when live enum
missed ``Describe*`` (wrong region, empty ListClusters, etc.). This module
materializes those as concrete nodes and wires the obvious EXECUTES_AS / RUNS_ON
edges so blast and HAS_MATERIAL have hosts to attach to.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.enrichment.impact import ensure_impact_target_node, get_impact_kind
from samoyed.enumerators.aws.ecs import analyze_ecs_task_definition, escape_native_id, workload_native_id
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.refs import resolve_node_ref

_PID_MODE = re.compile(r'\bpid_mode\s*=\s*"host"', re.I)
_HOST_VOLUME = re.compile(
    r'volume\s*\{[^}]*?name\s*=\s*"([^"]+)"[^}]*?host_path\s*=\s*"([^"]+)"',
    re.I | re.S,
)
_HOST_VOLUME_ALT = re.compile(
    r'volume\s*\{[^}]*?host_path\s*=\s*"([^"]+)"[^}]*?name\s*=\s*"([^"]+)"',
    re.I | re.S,
)


def project_declared_inventory(
    builder: GraphBuilder,
    *,
    declared_resources: list[dict[str, Any]] | None,
    report: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Ensure declared TF resources exist as graph nodes; wire ECS goat-style topology."""
    graph = builder.snapshot
    declared = [r for r in (declared_resources or []) if isinstance(r, dict) and r.get("name")]
    stats = {
        "declared_projected": 0,
        "ecs_workloads": 0,
        "ecs_hosts": 0,
        "escape_surfaces": 0,
        "edges_added": 0,
    }
    if not declared:
        return stats

    by_kind: dict[str, list[dict[str, Any]]] = {}
    for row in declared:
        by_kind.setdefault(str(row.get("kind") or ""), []).append(row)

    # 1) Project every registered kind (resolve existing when enum already has it).
    node_by_decl: dict[tuple[str, str], str] = {}
    for row in declared:
        kind = str(row.get("kind") or "")
        name = str(row.get("name") or "").strip()
        if not get_impact_kind(kind):
            continue
        before = set(graph.nodes)
        node_id = ensure_impact_target_node(builder, graph, name=name, kind=kind)
        node_by_decl[(kind, name.lower())] = node_id
        if node_id not in before:
            stats["declared_projected"] += 1
        node = graph.nodes.get(node_id)
        if node:
            node.props.setdefault("source", "collector-declared")
            if row.get("tf_address"):
                node.props.setdefault("tf_address", row["tf_address"])

    # 2) ECS topology from declared cluster/service/task + IAM roles.
    stats["edges_added"] += _wire_ecs_declared_topology(
        builder,
        graph,
        by_kind=by_kind,
        node_by_decl=node_by_decl,
        report=report or {},
        stats=stats,
    )
    return stats


def preferred_enrichment_host(graph: GraphSnapshot) -> str | None:
    """Prefer a projected ECS workload / ASG host for HAS_MATERIAL binding."""
    ranked: list[tuple[int, str]] = []
    for node_id, node in graph.nodes.items():
        reason = str(node.props.get("projected_reason") or "")
        if reason not in {"declared-ecs", "declared-asg"}:
            continue
        native = str(node.props.get("native_id") or "")
        if "*" in native:
            continue
        concept = str(node.props.get("concept_type") or "")
        rtype = str(node.props.get("resource_type") or "")
        if reason == "declared-ecs" and concept == "Workload":
            ranked.append((0, node_id))
        elif reason == "declared-asg" and rtype == "EC2Instance":
            ranked.append((1, node_id))
        elif reason == "declared-ecs" and rtype == "ECSService":
            ranked.append((2, node_id))
    if not ranked:
        return None
    ranked.sort(key=lambda item: item[0])
    return ranked[0][1]


def _wire_ecs_declared_topology(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    by_kind: dict[str, list[dict[str, Any]]],
    node_by_decl: dict[tuple[str, str], str],
    report: dict[str, Any],
    stats: dict[str, int],
) -> int:
    services = by_kind.get("ecs_service") or []
    clusters = by_kind.get("ecs_cluster") or []
    task_defs = by_kind.get("ecs_task_definition") or []
    if not services and not clusters and not task_defs:
        return 0

    task_role_id = _resolve_role(graph, by_kind, prefer=("ecs-task-role", "task-role", "task_role"))
    instance_role_id = _resolve_role(
        graph, by_kind, prefer=("ecs-instance-role", "instance-role", "ecs-instance")
    )

    # Synthetic ASG/EC2 host when we have an instance role (EC2 launch type).
    host_id: str | None = None
    asgs = by_kind.get("ec2_asg") or []
    edges_added = 0
    if instance_role_id:
        asg_name = str((asgs[0].get("name") if asgs else None) or "ecs-asg")
        host_native = f"EC2Instance:asg:{asg_name}"
        before = set(graph.nodes)
        host_id = builder.add_concept_node(
            concept_type=ConceptType.RUNTIME_BINDING,
            native_id=host_native,
            props={
                "resource_type": "EC2Instance",
                "native_kind": "EC2Instance",
                "name": asg_name,
                "display_name": f"ECS ASG host ({asg_name})",
                "asg_name": asg_name,
                "projected": True,
                "projected_reason": "declared-asg",
                "source": "collector-declared",
                "planned": True,
            },
        )
        if host_id not in before:
            stats["ecs_hosts"] += 1
        edges_added += _collapse_declared_asg_hosts(builder, graph, keep_id=host_id)
        if _upsert_edge(
            builder,
            graph,
            host_id,
            "EXECUTES_AS",
            instance_role_id,
            enrichment_edge_props(
                source="collector-declared",
                mechanism="asg-instance-profile",
                confidence="inferred",
            ),
        ):
            edges_added += 1

    cluster_id = None
    if clusters:
        cname = str(clusters[0].get("name") or "").strip()
        cluster_id = node_by_decl.get(("ecs_cluster", cname.lower()))

    td_blob = _load_task_definition_blob(report)
    containers = (td_blob or {}).get("containerDefinitions") or [{"name": "container"}]
    task_role_arn = None
    if task_role_id:
        role_node = graph.nodes.get(task_role_id)
        task_role_arn = (role_node.props.get("arn") if role_node else None) or (
            role_node.props.get("native_id") if role_node else None
        )

    for svc in services or [{"name": "ecs-service"}]:
        svc_name = str(svc.get("name") or "ecs-service").strip()
        svc_id = node_by_decl.get(("ecs_service", svc_name.lower()))
        if not svc_id:
            svc_id = ensure_impact_target_node(builder, graph, name=svc_name, kind="ecs_service")
        svc_node = graph.nodes.get(svc_id)
        if svc_node:
            svc_node.props["display_name"] = svc_name
            svc_node.props.setdefault("resource_type", "ECSService")
            svc_node.props.setdefault("projected_reason", "declared-ecs")

        if cluster_id and _upsert_edge(
            builder,
            graph,
            svc_id,
            "RUNS_ON",
            cluster_id,
            enrichment_edge_props(source="collector-declared", mechanism="ecs-service-cluster"),
        ):
            edges_added += 1

        if task_role_id and _upsert_edge(
            builder,
            graph,
            svc_id,
            "EXECUTES_AS",
            task_role_id,
            enrichment_edge_props(
                source="collector-declared",
                mechanism="ecs-task-role",
                role_kind="task",
            ),
        ):
            edges_added += 1

        if host_id and _upsert_edge(
            builder,
            graph,
            svc_id,
            "RUNS_ON",
            host_id,
            enrichment_edge_props(
                source="collector-declared",
                mechanism="ecs-on-ec2",
                planned=True,
            ),
        ):
            edges_added += 1

        scope_key = f"service/{svc_name}"
        workload_ids: list[tuple[str, str]] = []
        for container in containers:
            cname = str(container.get("name") or "container")
            wl_native = workload_native_id(scope_key, cname)
            before = set(graph.nodes)
            wl_id = builder.add_concept_node(
                concept_type=ConceptType.WORKLOAD,
                native_id=wl_native,
                props={
                    "resource_type": "ECSContainer",
                    "native_kind": "ECSContainer",
                    "container_name": cname,
                    "name": cname,
                    "display_name": f"{svc_name}/{cname}",
                    "image": container.get("image"),
                    "service_name": svc_name,
                    "projected": True,
                    "projected_reason": "declared-ecs",
                    "source": "collector-declared",
                    "from_service": True,
                },
            )
            if wl_id not in before:
                stats["ecs_workloads"] += 1
            workload_ids.append((wl_id, cname))

            if task_role_id and _upsert_edge(
                builder,
                graph,
                wl_id,
                "EXECUTES_AS",
                task_role_id,
                enrichment_edge_props(
                    source="collector-declared",
                    mechanism="ecs-task-role",
                    role_kind="task",
                ),
            ):
                edges_added += 1
            if host_id and _upsert_edge(
                builder,
                graph,
                wl_id,
                "RUNS_ON",
                host_id,
                enrichment_edge_props(
                    source="collector-declared",
                    mechanism="ecs-on-ec2",
                    planned=True,
                ),
            ):
                edges_added += 1

        td_for_analyze = dict(td_blob or {})
        if task_role_arn:
            td_for_analyze.setdefault("taskRoleArn", task_role_arn)
        if not td_for_analyze.get("containerDefinitions"):
            td_for_analyze["containerDefinitions"] = containers
        findings = analyze_ecs_task_definition(td_for_analyze, scope_key=scope_key)
        for finding in findings:
            kind = finding["kind"]
            esc_native = finding.get("native_id") or escape_native_id(scope_key, kind)
            if kind in {"container-credentials", "hostPID", "hostIPC", "hostNetwork"}:
                esc_native = escape_native_id(scope_key, kind)
            before = set(graph.nodes)
            esc_id = builder.add_concept_node(
                concept_type=ConceptType.ESCAPE_SURFACE,
                native_id=esc_native,
                props={
                    "resource_type": "ECSEscape",
                    "escape_kind": kind,
                    "display_name": finding.get("description") or kind,
                    "severity": finding.get("severity"),
                    "projected": True,
                    "projected_reason": "declared-ecs",
                    "source": "collector-declared",
                },
            )
            if esc_id not in before:
                stats["escape_surfaces"] += 1
            finding_container = finding.get("container")
            linked = [
                wl_id
                for wl_id, cname in workload_ids
                if finding_container is None or finding_container == cname
            ] or ([workload_ids[0][0]] if workload_ids else [])
            for wl_id in linked:
                if _upsert_edge(
                    builder,
                    graph,
                    wl_id,
                    "HAS_ESCAPE_SURFACE",
                    esc_id,
                    enrichment_edge_props(
                        source="collector-declared",
                        mechanism=kind,
                        severity=finding.get("severity"),
                    ),
                ):
                    edges_added += 1
            if kind == "container-credentials" and task_role_id:
                if _upsert_edge(
                    builder,
                    graph,
                    esc_id,
                    "EXECUTES_AS",
                    task_role_id,
                    enrichment_edge_props(
                        source="collector-declared",
                        mechanism="ecs-container-credentials",
                        endpoint="169.254.170.2",
                        role_kind="task",
                    ),
                ):
                    edges_added += 1
            elif host_id and kind != "container-credentials":
                if _upsert_edge(
                    builder,
                    graph,
                    esc_id,
                    "CAN_ESCAPE_TO",
                    host_id,
                    enrichment_edge_props(
                        source="collector-declared",
                        mechanism=kind,
                        planned=True,
                    ),
                ):
                    edges_added += 1

    return edges_added


def _collapse_declared_asg_hosts(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    keep_id: str,
) -> int:
    """Retarget edges from older synthetic ASG stubs onto the canonical host."""
    edges_added = 0
    orphans = [
        nid
        for nid, node in list(graph.nodes.items())
        if nid != keep_id and node.props.get("projected_reason") == "declared-asg"
    ]
    for old_id in orphans:
        for edge in list(graph.edges):
            if edge.src_id == old_id:
                if _upsert_edge(builder, graph, keep_id, edge.rel_type, edge.dst_id, dict(edge.props)):
                    edges_added += 1
            elif edge.dst_id == old_id:
                if _upsert_edge(builder, graph, edge.src_id, edge.rel_type, keep_id, dict(edge.props)):
                    edges_added += 1
        graph.remove_node(old_id)
    return edges_added


def _resolve_role(
    graph: GraphSnapshot,
    by_kind: dict[str, list[dict[str, Any]]],
    *,
    prefer: tuple[str, ...],
) -> str | None:
    roles = by_kind.get("iam_role") or []
    for pref in prefer:
        for row in roles:
            name = str(row.get("name") or "")
            if pref.lower() in name.lower():
                hit = resolve_node_ref(graph, name, prefer_concepts=("identity", "role"))
                if hit:
                    return hit
    for row in roles:
        name = str(row.get("name") or "")
        hit = resolve_node_ref(graph, name, prefer_concepts=("identity", "role"))
        if hit:
            return hit
    return None


def _load_task_definition_blob(report: dict[str, Any]) -> dict[str, Any] | None:
    """Load container definitions (+ TF pid_mode/host volumes) from the collected module."""
    root = report.get("source_root")
    if not root:
        return None
    base = Path(str(root))
    candidates = [
        base / "resources" / "ecs" / "task_definition.json",
        base / "task_definition.json",
    ]
    td: dict[str, Any] = {}
    for path in candidates:
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(raw, list):
            td = {"containerDefinitions": raw}
        elif isinstance(raw, dict):
            td = dict(raw)
        break
    if not td:
        td = {"containerDefinitions": [{"name": "container"}]}

    _augment_from_terraform(td, base)
    return td


def _augment_from_terraform(td: dict[str, Any], base: Path) -> None:
    """Merge pid_mode / host volumes from *.tf (not always present in the JSON template)."""
    texts: list[str] = []
    for path in sorted(base.glob("*.tf")):
        try:
            texts.append(path.read_text(encoding="utf-8"))
        except OSError:
            continue
    if not texts:
        return
    blob = "\n".join(texts)
    if _PID_MODE.search(blob):
        td.setdefault("pidMode", "host")
    volumes = list(td.get("volumes") or [])
    seen = {str(v.get("name") or "") for v in volumes if isinstance(v, dict)}
    for match in _HOST_VOLUME.finditer(blob):
        name, host_path = match.group(1), match.group(2)
        if name in seen:
            continue
        volumes.append({"name": name, "host": {"sourcePath": host_path}})
        seen.add(name)
    for match in _HOST_VOLUME_ALT.finditer(blob):
        host_path, name = match.group(1), match.group(2)
        if name in seen:
            continue
        volumes.append({"name": name, "host": {"sourcePath": host_path}})
        seen.add(name)
    if volumes:
        td["volumes"] = volumes


def _upsert_edge(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    src: str,
    rel: str,
    dst: str,
    props: dict[str, Any],
) -> bool:
    for edge in graph.edges:
        if edge.src_id == src and edge.dst_id == dst and edge.rel_type == rel:
            edge.props.update(props)
            return False
    builder.add_edge(src_id=src, rel_type=rel, dst_id=dst, props=props)
    return True
