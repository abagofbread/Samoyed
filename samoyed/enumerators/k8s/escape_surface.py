from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.k8s import pod_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.k8s.helpers import call_k8s
from samoyed.enumerators.k8s.nodes import cluster_host_native_id, node_native_id
from samoyed.enumerators.k8s.workloads import pod_spec_dict


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

DANGEROUS_CAPS = frozenset(
    {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "NET_ADMIN",
        "CAP_SYS_ADMIN",
    }
)


def analyze_pod_spec(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Pure-function escape surface analysis for unit tests and live enum."""
    findings: list[dict[str, Any]] = []
    meta = spec.get("metadata") or {}
    namespace = meta.get("namespace", "default")
    pod_name = meta.get("name", "unknown")
    pod_spec = spec.get("spec") or {}

    if pod_spec.get("hostPID"):
        findings.append(_finding(namespace, pod_name, "hostPID", "Pod shares host PID namespace"))
    if pod_spec.get("hostNetwork"):
        findings.append(_finding(namespace, pod_name, "hostNetwork", "Pod uses host network"))
    if pod_spec.get("hostIPC"):
        findings.append(_finding(namespace, pod_name, "hostIPC", "Pod shares host IPC namespace"))

    host_paths = _host_paths(pod_spec)
    for path in host_paths:
        if any(path == d or path.startswith(d.rstrip("/") + "/") or path == d for d in DANGEROUS_HOST_PATHS):
            findings.append(
                _finding(namespace, pod_name, "hostPath", f"hostPath mount: {path}", severity="critical")
            )

    for container in list(pod_spec.get("containers") or []) + list(pod_spec.get("initContainers") or []):
        cname = container.get("name", "container")
        sc = container.get("securityContext") or {}
        if sc.get("privileged"):
            findings.append(
                _finding(namespace, pod_name, "privileged", f"Container {cname} is privileged", severity="critical")
            )
        if sc.get("allowPrivilegeEscalation") is True:
            findings.append(
                _finding(
                    namespace,
                    pod_name,
                    "allowPrivilegeEscalation",
                    f"Container {cname} allows privilege escalation",
                    severity="medium",
                )
            )
        caps = ((sc.get("capabilities") or {}).get("add") or [])
        for cap in caps:
            cap_name = cap.upper().replace("CAP_", "")
            if cap_name in DANGEROUS_CAPS or cap.upper() in DANGEROUS_CAPS:
                findings.append(
                    _finding(namespace, pod_name, "capabilities", f"Container {cname} adds {cap}", severity="high")
                )
        for mount in container.get("volumeMounts") or []:
            mpath = mount.get("mountPath", "")
            if "docker.sock" in mpath or "containerd.sock" in mpath or "crio.sock" in mpath:
                findings.append(
                    _finding(
                        namespace,
                        pod_name,
                        "docker-socket",
                        f"Container {cname} mounts runtime socket at {mpath}",
                        severity="critical",
                    )
                )

    return findings


def _finding(namespace: str, pod_name: str, kind: str, description: str, severity: str = "medium") -> dict[str, Any]:
    return {
        "namespace": namespace,
        "pod": pod_name,
        "kind": kind,
        "description": description,
        "severity": severity,
        "native_id": f"kubernetes:escape:{namespace}:{pod_name}:{kind}",
    }


def _host_paths(pod_spec: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for vol in pod_spec.get("volumes") or []:
        hp = vol.get("hostPath") or {}
        if hp.get("path"):
            paths.append(hp["path"])
    return paths


class K8sEscapeSurfaceAnalyzer:
    concept = ConceptType.ESCAPE_SURFACE
    name = "k8s-escape-surface"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        core = cred.client("core")  # type: ignore[attr-defined]
        cluster = ctx.scope.properties.get("cluster", "cluster")
        host_id = cluster_host_native_id(cluster)

        ns_list = call_k8s(ctx, operation="core/v1:namespaces", call=lambda: core.list_namespace())
        namespaces = [ns.metadata.name for ns in ns_list.items] if ns_list else ["default"]

        for namespace in namespaces:
            pods = call_k8s(
                ctx,
                operation=f"core/v1:pods:{namespace}",
                call=lambda ns=namespace: core.list_namespaced_pod(namespace=ns),
            )
            if not pods:
                continue
            for pod in pods.items:
                spec = pod_spec_dict(pod)
                findings = analyze_pod_spec(spec)
                pod_id = pod_native_id(namespace, pod.metadata.name)
                node_name = (spec.get("spec") or {}).get("nodeName")
                landing = node_native_id(cluster, node_name) if node_name else host_id
                for finding in findings:
                    edges = [
                        ConceptEdge(
                            rel_type="HAS_ESCAPE_SURFACE",
                            src_native_id=pod_id,
                            target_native_id=finding["native_id"],
                            target_concept_type=ConceptType.ESCAPE_SURFACE,
                            props={"kind": finding["kind"]},
                        ),
                        ConceptEdge(
                            rel_type="CAN_ESCAPE_TO",
                            src_native_id=finding["native_id"],
                            target_native_id=landing,
                            target_concept_type=ConceptType.RUNTIME_BINDING,
                            props={
                                "target": "node" if node_name else "node/host",
                                "node": node_name,
                                "severity": finding["severity"],
                                "mechanism": finding["kind"],
                            },
                            confidence=ConfidenceType.EXPLICIT,
                        ),
                    ]
                    # Always also bridge to cluster host so unsched paths still work
                    if node_name and landing != host_id:
                        edges.append(
                            ConceptEdge(
                                rel_type="CAN_ESCAPE_TO",
                                src_native_id=finding["native_id"],
                                target_native_id=host_id,
                                target_concept_type=ConceptType.RUNTIME_BINDING,
                                props={
                                    "target": "node/host",
                                    "severity": finding["severity"],
                                    "mechanism": finding["kind"],
                                },
                            )
                        )
                    yield ConceptArtifact(
                        concept_type=ConceptType.ESCAPE_SURFACE,
                        provider=CloudProvider.KUBERNETES,
                        native_id=finding["native_id"],
                        scope_id=ctx.scope.scope_id,
                        properties={
                            **finding,
                            "display_name": finding["description"],
                            "node_name": node_name,
                        },
                        evidence=Evidence("core/v1:pods:escape-analysis", {"pod": pod_id}),
                        confidence=ConfidenceType.EXPLICIT,
                        edges=edges,
                    )
