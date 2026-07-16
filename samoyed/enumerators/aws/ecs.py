"""ECS topology + container escape surfaces.

Mirrors K8s workload/escape patterns for EC2-launch ECS (AWSGoat Module 2 style):

  Workload (container) ──EXECUTES_AS──► task role
       │                    │
       │                    └── via EscapeSurface(container-credentials) @ 169.254.170.2
       ├──RUNS_ON──► EC2Instance ──EXECUTES_AS──► instance profile role
       └──HAS_ESCAPE_SURFACE──► privileged / SYS_PTRACE / …
                                    └──CAN_ESCAPE_TO──► same EC2Instance
"""

from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.aws.runtime_bindings import executes_as_edge
from samoyed.enumerators.runner import paginate_call
from samoyed.graph.resource_scope import parse_ecr_image_uri

# Aligned with k8s/escape_surface.DANGEROUS_CAPS (SYS_PTRACE is the AWSGoat M2 path).
DANGEROUS_CAPS = frozenset(
    {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "NET_ADMIN",
        "CAP_SYS_ADMIN",
        "CAP_SYS_PTRACE",
    }
)

DANGEROUS_HOST_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/crio/crio.sock",
    "/var/run/containerd.sock",
    "/",
    "/etc",
    "/proc",
    "/sys",
)


def task_native_id(task_arn: str) -> str:
    return f"ECSTask:{task_arn}"


def workload_native_id(task_or_service_key: str, container_name: str) -> str:
    return f"ECSContainer:{task_or_service_key}/{container_name}"


def escape_native_id(scope_key: str, kind: str, container: str | None = None) -> str:
    base = f"aws:ecs:escape:{scope_key}:{kind}"
    return f"{base}:{container}" if container else base


def analyze_ecs_container_definition(
    container: dict[str, Any],
    *,
    scope_key: str,
    host_volumes: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Pure-function escape analysis for one container definition."""
    findings: list[dict[str, Any]] = []
    cname = container.get("name") or "container"
    host_volumes = host_volumes or {}

    if container.get("privileged"):
        findings.append(
            _finding(
                scope_key,
                "privileged",
                f"Container {cname} is privileged",
                severity="critical",
                container=cname,
            )
        )

    caps = ((container.get("linuxParameters") or {}).get("capabilities") or {}).get("add") or []
    for cap in caps:
        cap_norm = str(cap).upper().replace("CAP_", "")
        if cap_norm in DANGEROUS_CAPS or str(cap).upper() in DANGEROUS_CAPS:
            findings.append(
                _finding(
                    scope_key,
                    "capabilities",
                    f"Container {cname} adds {cap}",
                    severity="high",
                    container=cname,
                )
            )

    for mount in container.get("mountPoints") or []:
        source = mount.get("sourceVolume") or ""
        host_path = host_volumes.get(source, "")
        mpath = mount.get("containerPath") or ""
        if "docker.sock" in mpath or "docker.sock" in host_path:
            findings.append(
                _finding(
                    scope_key,
                    "docker-socket",
                    f"Container {cname} mounts docker socket ({host_path or mpath})",
                    severity="critical",
                    container=cname,
                )
            )
        elif host_path and _dangerous_host_path(host_path):
            findings.append(
                _finding(
                    scope_key,
                    "hostPath",
                    f"Container {cname} mounts host path {host_path}",
                    severity="critical",
                    container=cname,
                )
            )

    return findings


def analyze_ecs_task_definition(task_def: dict[str, Any], *, scope_key: str) -> list[dict[str, Any]]:
    """Pure-function escape analysis for a DescribeTaskDefinition payload."""
    findings: list[dict[str, Any]] = []
    if task_def.get("pidMode") == "host":
        findings.append(_finding(scope_key, "hostPID", "Task shares host PID namespace", severity="high"))
    if task_def.get("ipcMode") == "host":
        findings.append(_finding(scope_key, "hostIPC", "Task shares host IPC namespace", severity="medium"))
    if task_def.get("networkMode") == "host":
        findings.append(_finding(scope_key, "hostNetwork", "Task uses host network mode", severity="medium"))

    host_volumes = _host_volumes(task_def)
    for container in task_def.get("containerDefinitions") or []:
        findings.extend(
            analyze_ecs_container_definition(container, scope_key=scope_key, host_volumes=host_volumes)
        )

    if task_def.get("taskRoleArn"):
        findings.append(
            _finding(
                scope_key,
                "container-credentials",
                "Task role available via ECS container credentials endpoint (169.254.170.2)",
                severity="high",
            )
        )
    return findings


def _finding(
    scope_key: str,
    kind: str,
    description: str,
    *,
    severity: str = "medium",
    container: str | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "description": description,
        "severity": severity,
        "container": container,
        "scope_key": scope_key,
        "native_id": escape_native_id(scope_key, kind, container),
    }


def _host_volumes(task_def: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for vol in task_def.get("volumes") or []:
        name = vol.get("name")
        host = vol.get("host") or {}
        path = host.get("sourcePath")
        if name and path:
            mapping[name] = path
    return mapping


def _dangerous_host_path(path: str) -> bool:
    for d in DANGEROUS_HOST_PATHS:
        if path == d or path.startswith(d.rstrip("/") + "/"):
            return True
    return False


def enumerate_ecs_topology(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    """Enumerate ECS clusters: tasks, workloads, container hosts, and escape surfaces."""
    cred = ctx.credentials
    ecs = cred.client("ecs")  # type: ignore[attr-defined]
    clusters = paginate_call(ctx, operation="ecs:ListClusters", call=lambda: ecs.list_clusters())
    if not clusters:
        return

    for cluster_arn in clusters.get("clusterArns", []) or []:
        ci_to_ec2 = dict(_container_instance_ec2_map(ctx, ecs, cluster_arn))
        task_defs: dict[str, dict[str, Any]] = {}
        seen_td_arns: set[str] = set()

        for artifact in _enumerate_running_tasks(ctx, ecs, cluster_arn, ci_to_ec2, task_defs, seen_td_arns):
            yield artifact

        for artifact in _enumerate_services(ctx, ecs, cluster_arn, ci_to_ec2, task_defs, seen_td_arns):
            yield artifact


def enumerate_ecs_task_roles(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    """Backward-compatible entry point — full ECS topology + escapes."""
    yield from enumerate_ecs_topology(ctx)


def _container_instance_ec2_map(
    ctx: EnumContext, ecs: Any, cluster_arn: str
) -> Iterator[tuple[str, str]]:
    listed = paginate_call(
        ctx,
        operation="ecs:ListContainerInstances",
        call=lambda c=cluster_arn: ecs.list_container_instances(cluster=c),
    )
    if not listed:
        return
    arns = listed.get("containerInstanceArns") or []
    if not arns:
        return
    # Describe up to 100 at a time (API limit).
    for i in range(0, len(arns), 100):
        batch = arns[i : i + 100]
        desc = paginate_call(
            ctx,
            operation="ecs:DescribeContainerInstances",
            call=lambda c=cluster_arn, b=batch: ecs.describe_container_instances(
                cluster=c, containerInstances=b
            ),
        )
        if not desc:
            continue
        for ci in desc.get("containerInstances") or []:
            ci_arn = ci.get("containerInstanceArn")
            ec2_id = ci.get("ec2InstanceId")
            if ci_arn and ec2_id:
                yield ci_arn, ec2_id


def _describe_task_definition(
    ctx: EnumContext,
    ecs: Any,
    td_arn: str,
    cache: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    if td_arn in cache:
        return cache[td_arn]
    resp = paginate_call(
        ctx,
        operation="ecs:DescribeTaskDefinition",
        call=lambda a=td_arn: ecs.describe_task_definition(taskDefinition=a),
    )
    if not resp:
        return None
    td = resp.get("taskDefinition") or {}
    cache[td_arn] = td
    return td


def _enumerate_running_tasks(
    ctx: EnumContext,
    ecs: Any,
    cluster_arn: str,
    ci_to_ec2: dict[str, str],
    task_defs: dict[str, dict[str, Any]],
    seen_td_arns: set[str],
) -> Iterator[ConceptArtifact]:
    listed = paginate_call(
        ctx,
        operation="ecs:ListTasks",
        call=lambda c=cluster_arn: ecs.list_tasks(cluster=c),
    )
    if not listed:
        return
    task_arns = listed.get("taskArns") or []
    if not task_arns:
        return

    for i in range(0, len(task_arns), 100):
        batch = task_arns[i : i + 100]
        desc = paginate_call(
            ctx,
            operation="ecs:DescribeTasks",
            call=lambda c=cluster_arn, b=batch: ecs.describe_tasks(cluster=c, tasks=b),
        )
        if not desc:
            continue
        for task in desc.get("tasks") or []:
            yield from _emit_task_topology(ctx, ecs, cluster_arn, task, ci_to_ec2, task_defs, seen_td_arns)


def _emit_task_topology(
    ctx: EnumContext,
    ecs: Any,
    cluster_arn: str,
    task: dict[str, Any],
    ci_to_ec2: dict[str, str],
    task_defs: dict[str, dict[str, Any]],
    seen_td_arns: set[str],
) -> Iterator[ConceptArtifact]:
    task_arn = task.get("taskArn") or ""
    if not task_arn:
        return
    td_arn = task.get("taskDefinitionArn") or ""
    task_role = task.get("taskRoleArn")
    exec_role = task.get("executionRoleArn")
    launch_type = task.get("launchType") or ""
    ci_arn = task.get("containerInstanceArn")
    ec2_id = ci_to_ec2.get(ci_arn or "") if ci_arn else None
    host_native_id = f"EC2Instance:{ec2_id}" if ec2_id else None

    td: dict[str, Any] | None = None
    if td_arn:
        td = _describe_task_definition(ctx, ecs, td_arn, task_defs)
        seen_td_arns.add(td_arn)
        # Prefer role ARNs from the live task; fall back to task definition.
        if td:
            task_role = task_role or td.get("taskRoleArn")
            exec_role = exec_role or td.get("executionRoleArn")

    task_id = task_native_id(task_arn)
    edges: list[ConceptEdge] = []
    if task_role:
        edges.append(
            executes_as_edge(
                task_role,
                resource_type="ECSTask",
                task_arn=task_arn,
                role_kind="task",
            )
        )
    if exec_role and exec_role != task_role:
        edges.append(
            executes_as_edge(
                exec_role,
                resource_type="ECSTask",
                task_arn=task_arn,
                role_kind="execution",
            )
        )
    if host_native_id:
        edges.append(
            ConceptEdge(
                rel_type="RUNS_ON",
                target_native_id=host_native_id,
                target_concept_type=ConceptType.RUNTIME_BINDING,
                props={
                    "resource_type": "EC2Instance",
                    "instance_id": ec2_id,
                    "container_instance_arn": ci_arn,
                    "launch_type": launch_type or "EC2",
                },
                confidence=ConfidenceType.EXPLICIT,
            )
        )

    yield ConceptArtifact(
        concept_type=ConceptType.RUNTIME_BINDING,
        provider=CloudProvider.AWS,
        native_id=task_id,
        scope_id=ctx.scope.scope_id,
        properties={
            "resource_type": "ECSTask",
            "task_arn": task_arn,
            "cluster_arn": cluster_arn,
            "task_definition_arn": td_arn,
            "task_role_arn": task_role,
            "execution_role_arn": exec_role,
            "launch_type": launch_type,
            "container_instance_arn": ci_arn,
            "ec2_instance_id": ec2_id,
            "display_name": _short_arn(task_arn),
        },
        evidence=Evidence("ecs:DescribeTasks", {"task_arn": task_arn}),
        edges=edges,
    )

    containers = (td or {}).get("containerDefinitions") or []
    if not containers:
        # Live task still lists container names even without a task-def fetch.
        containers = [
            {"name": c.get("name") or "container", "image": c.get("image")}
            for c in (task.get("containers") or [])
        ]
        if not containers:
            containers = [{"name": "task"}]

    workload_ids: list[tuple[str, str]] = []
    for container in containers:
        cname = container.get("name") or "container"
        wl_id = workload_native_id(task_arn, cname)
        workload_ids.append((wl_id, cname))
        wl_edges: list[ConceptEdge] = []
        if task_role:
            wl_edges.append(
                executes_as_edge(
                    task_role,
                    resource_type="ECSContainer",
                    task_arn=task_arn,
                    role_kind="task",
                )
            )
        if host_native_id:
            wl_edges.append(
                ConceptEdge(
                    rel_type="RUNS_ON",
                    target_native_id=host_native_id,
                    target_concept_type=ConceptType.RUNTIME_BINDING,
                    props={
                        "resource_type": "EC2Instance",
                        "instance_id": ec2_id,
                        "launch_type": launch_type or "EC2",
                    },
                    confidence=ConfidenceType.EXPLICIT,
                )
            )

        wl_edges.extend(_workload_resource_edges(container))

        yield ConceptArtifact(
            concept_type=ConceptType.WORKLOAD,
            provider=CloudProvider.AWS,
            native_id=wl_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "resource_type": "ECSContainer",
                "native_kind": "ECSContainer",
                "task_arn": task_arn,
                "cluster_arn": cluster_arn,
                "container_name": cname,
                "image": container.get("image"),
                "task_role_arn": task_role,
                "ec2_instance_id": ec2_id,
                "display_name": f"{_short_arn(task_arn)}/{cname}",
            },
            evidence=Evidence("ecs:DescribeTasks", {"task_arn": task_arn, "container": cname}),
            edges=wl_edges,
        )

    # Escapes once per finding; HAS_ESCAPE_SURFACE from every container workload.
    yield from _emit_escape_surfaces(
        ctx,
        scope_key=task_arn,
        workload_ids=workload_ids,
        task_def=td or {"taskRoleArn": task_role},
        host_native_id=host_native_id,
        task_role=task_role,
        evidence_op="ecs:DescribeTaskDefinition",
    )


def _enumerate_services(
    ctx: EnumContext,
    ecs: Any,
    cluster_arn: str,
    ci_to_ec2: dict[str, str],
    task_defs: dict[str, dict[str, Any]],
    seen_td_arns: set[str],
) -> Iterator[ConceptArtifact]:
    """Emit service + task-def topology when apps exist even if no tasks are RUNNING."""
    listed = paginate_call(
        ctx,
        operation="ecs:ListServices",
        call=lambda c=cluster_arn: ecs.list_services(cluster=c),
    )
    if not listed:
        return
    service_arns = listed.get("serviceArns") or []
    if not service_arns:
        return

    # Representative host for planned escape paths when cluster capacity exists.
    host_native_id: str | None = None
    if ci_to_ec2:
        host_native_id = f"EC2Instance:{next(iter(ci_to_ec2.values()))}"

    for i in range(0, len(service_arns), 10):
        batch = service_arns[i : i + 10]
        desc = paginate_call(
            ctx,
            operation="ecs:DescribeServices",
            call=lambda c=cluster_arn, b=batch: ecs.describe_services(cluster=c, services=b),
        )
        if not desc:
            continue
        for svc in desc.get("services") or []:
            td_arn = svc.get("taskDefinition") or ""
            # Skip when running tasks already covered this task-def revision.
            if not td_arn or td_arn in seen_td_arns:
                continue
            service_arn = svc.get("serviceArn") or ""
            if not service_arn:
                continue
            td = _describe_task_definition(ctx, ecs, td_arn, task_defs)
            seen_td_arns.add(td_arn)
            task_role = (td or {}).get("taskRoleArn")
            exec_role = (td or {}).get("executionRoleArn")
            launch_type = (svc.get("launchType") or "") or (
                (svc.get("capacityProviderStrategy") or [{}])[0].get("capacityProvider") or ""
            )

            # Service-level RuntimeBinding for the desired task shape.
            svc_task_key = f"service/{service_arn}"
            rb_id = f"ECSServiceBinding:{service_arn}"
            rb_edges: list[ConceptEdge] = []
            if task_role:
                rb_edges.append(
                    executes_as_edge(
                        task_role,
                        resource_type="ECSService",
                        service_arn=service_arn,
                        role_kind="task",
                    )
                )
            if exec_role and exec_role != task_role:
                rb_edges.append(
                    executes_as_edge(
                        exec_role,
                        resource_type="ECSService",
                        service_arn=service_arn,
                        role_kind="execution",
                    )
                )
            if host_native_id:
                rb_edges.append(
                    ConceptEdge(
                        rel_type="RUNS_ON",
                        target_native_id=host_native_id,
                        target_concept_type=ConceptType.RUNTIME_BINDING,
                        props={
                            "resource_type": "EC2Instance",
                            "planned": True,
                            "launch_type": launch_type or "EC2",
                        },
                        confidence=ConfidenceType.WILDCARD,
                    )
                )

            yield ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.AWS,
                native_id=rb_id,
                scope_id=ctx.scope.scope_id,
                properties={
                    "resource_type": "ECSService",
                    "service_arn": service_arn,
                    "service_name": svc.get("serviceName"),
                    "cluster_arn": cluster_arn,
                    "task_definition_arn": td_arn,
                    "task_role_arn": task_role,
                    "execution_role_arn": exec_role,
                    "desired_count": svc.get("desiredCount"),
                    "running_count": svc.get("runningCount"),
                    "launch_type": launch_type,
                    "display_name": svc.get("serviceName") or _short_arn(service_arn),
                },
                evidence=Evidence("ecs:DescribeServices", {"service_arn": service_arn}),
                edges=rb_edges,
            )

            containers = (td or {}).get("containerDefinitions") or [{"name": "service"}]
            workload_ids: list[tuple[str, str]] = []
            for container in containers:
                cname = container.get("name") or "container"
                wl_id = workload_native_id(svc_task_key, cname)
                workload_ids.append((wl_id, cname))
                wl_edges: list[ConceptEdge] = []
                if task_role:
                    wl_edges.append(
                        executes_as_edge(
                            task_role,
                            resource_type="ECSContainer",
                            service_arn=service_arn,
                            role_kind="task",
                        )
                    )
                if host_native_id:
                    wl_edges.append(
                        ConceptEdge(
                            rel_type="RUNS_ON",
                            target_native_id=host_native_id,
                            target_concept_type=ConceptType.RUNTIME_BINDING,
                            props={"planned": True, "resource_type": "EC2Instance"},
                            confidence=ConfidenceType.WILDCARD,
                        )
                    )
                wl_edges.extend(_workload_resource_edges(container))
                yield ConceptArtifact(
                    concept_type=ConceptType.WORKLOAD,
                    provider=CloudProvider.AWS,
                    native_id=wl_id,
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "resource_type": "ECSContainer",
                        "native_kind": "ECSContainer",
                        "service_arn": service_arn,
                        "cluster_arn": cluster_arn,
                        "container_name": cname,
                        "image": container.get("image"),
                        "task_role_arn": task_role,
                        "display_name": f"{svc.get('serviceName') or _short_arn(service_arn)}/{cname}",
                        "from_service": True,
                    },
                    evidence=Evidence(
                        "ecs:DescribeServices",
                        {"service_arn": service_arn, "container": cname},
                    ),
                    edges=wl_edges,
                )

            yield from _emit_escape_surfaces(
                ctx,
                scope_key=svc_task_key,
                workload_ids=workload_ids,
                task_def=td or {"taskRoleArn": task_role},
                host_native_id=host_native_id,
                task_role=task_role,
                evidence_op="ecs:DescribeServices",
                planned=True,
            )


def _emit_escape_surfaces(
    ctx: EnumContext,
    *,
    scope_key: str,
    workload_ids: list[tuple[str, str]],
    task_def: dict[str, Any],
    host_native_id: str | None,
    task_role: str | None,
    evidence_op: str,
    planned: bool = False,
) -> Iterator[ConceptArtifact]:
    """Emit one EscapeSurface per finding; link HAS_ESCAPE_SURFACE from relevant workloads."""
    findings = analyze_ecs_task_definition(task_def, scope_key=scope_key)
    for finding in findings:
        kind = finding["kind"]
        escape_id = finding["native_id"]
        if kind in {"container-credentials", "hostPID", "hostIPC", "hostNetwork"}:
            escape_id = escape_native_id(scope_key, kind)

        # Task-scoped findings attach to all containers; container-scoped only to matching ones.
        finding_container = finding.get("container")
        linked = [
            wl_id
            for wl_id, cname in workload_ids
            if finding_container is None or finding_container == cname
        ]
        if not linked and workload_ids:
            linked = [workload_ids[0][0]]
        if not linked:
            continue

        edges = [
            ConceptEdge(
                rel_type="HAS_ESCAPE_SURFACE",
                src_native_id=wl_id,
                target_native_id=escape_id,
                target_concept_type=ConceptType.ESCAPE_SURFACE,
                props={"kind": kind, **({"planned": True} if planned else {})},
            )
            for wl_id in linked
        ]

        if kind == "container-credentials" and task_role:
            edges.append(
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    src_native_id=escape_id,
                    target_native_id=task_role,
                    target_concept_type=ConceptType.IDENTITY,
                    props={
                        "mechanism": "ecs-container-credentials",
                        "endpoint": "169.254.170.2",
                        "role_kind": "task",
                        "role_arn": task_role,
                    },
                    confidence=ConfidenceType.EXPLICIT,
                )
            )
        elif kind != "container-credentials" and host_native_id:
            edges.append(
                ConceptEdge(
                    rel_type="CAN_ESCAPE_TO",
                    src_native_id=escape_id,
                    target_native_id=host_native_id,
                    target_concept_type=ConceptType.RUNTIME_BINDING,
                    props={
                        "target": "ec2/host",
                        "severity": finding["severity"],
                        "kind": kind,
                        **({"planned": True} if planned else {}),
                    },
                    confidence=ConfidenceType.WILDCARD if planned else ConfidenceType.EXPLICIT,
                )
            )

        yield ConceptArtifact(
            concept_type=ConceptType.ESCAPE_SURFACE,
            provider=CloudProvider.AWS,
            native_id=escape_id,
            scope_id=ctx.scope.scope_id,
            properties={
                **finding,
                "native_id": escape_id,
                "display_name": finding["description"],
                "resource_type": "ECSEscape",
                "provider": "aws",
            },
            evidence=Evidence(evidence_op, {"scope_key": scope_key, "kind": kind}),
            confidence=ConfidenceType.EXPLICIT,
            edges=edges,
        )


def _workload_resource_edges(container: dict[str, Any]) -> list[ConceptEdge]:
    """USES_IMAGE / PULLS_FROM (ECR) / READS (Secrets Manager) for a container def."""
    edges: list[ConceptEdge] = []
    if container.get("image"):
        image = container["image"]
        image_id = f"aws:ecs:image:{image}"
        edges.append(
            ConceptEdge(
                rel_type="USES_IMAGE",
                target_native_id=image_id,
                target_concept_type=ConceptType.IMAGE_PROVENANCE,
                props={"image": image},
            )
        )
        ecr = parse_ecr_image_uri(image)
        if ecr:
            edges.append(
                ConceptEdge(
                    rel_type="PULLS_FROM",
                    src_native_id=image_id,
                    target_native_id=ecr.canonical_id,
                    target_concept_type=ConceptType.REGISTRY_STORE,
                    props={
                        "image": image,
                        "resource": ecr.pattern,
                        "resource_type": "ECRRepository",
                        **({"image_tag": ecr.image_tag} if ecr.image_tag else {}),
                    },
                )
            )
    for secret_ref in _container_secret_refs(container):
        edges.append(
            ConceptEdge(
                rel_type="READS",
                target_native_id=secret_ref,
                target_concept_type=ConceptType.SECRET_STORE,
                props={
                    "resource": secret_ref.split(":", 1)[-1],
                    "resource_type": "Secret",
                    "source": "ecs-task-def",
                },
            )
        )
    return edges


def _container_secret_refs(container: dict[str, Any]) -> list[str]:
    """Normalize ECS secrets[].valueFrom to Secret:{arn} native ids."""
    refs: list[str] = []
    for entry in container.get("secrets") or []:
        value_from = entry.get("valueFrom") or ""
        if not value_from:
            continue
        if value_from.startswith("arn:aws:secretsmanager:"):
            # SSM/JSON key suffix :key — strip trailing :json-key when present after the random suffix
            arn = value_from
            # valueFrom may be arn:...:secret:name-XXXXXX:KEY
            parts = arn.split(":secret:", 1)
            if len(parts) == 2 and ":" in parts[1]:
                # Keep name-XXXXXX, drop :KEY
                name_part = parts[1].rsplit(":", 1)[0]
                arn = f"{parts[0]}:secret:{name_part}"
            refs.append(f"Secret:{arn}")
        elif value_from.startswith("arn:aws:ssm:"):
            from samoyed.graph.resource_scope import resolve_policy_resource

            nid, _ = resolve_policy_resource(value_from, "SSMParameter")
            refs.append(nid)
        elif value_from.startswith("/"):
            refs.append(f"SSMParameter:{value_from.lstrip('/')}")
    return refs


def _short_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if arn else arn
