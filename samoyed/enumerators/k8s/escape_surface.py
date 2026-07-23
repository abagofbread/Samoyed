from __future__ import annotations

from typing import Any

from samoyed.cloud.artifacts import ConceptEdge
from samoyed.cloud.concepts import ConceptType, ConfidenceType


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


def escape_edges(
    findings: list[dict[str, Any]],
    *,
    landing: str,
    host_id: str,
) -> list[ConceptEdge]:
    """Parallel ``CAN_ESCAPE_TO`` edges — one per escape technique.

    A container escape is a *transition*, not an intermediate node: each finding
    becomes a mechanism-labeled edge from the pod to the node it lands on. When a
    pod is scheduled on a named node we also bridge to the synthetic cluster host
    so unscheduled/unknown-node paths still resolve a landing zone.
    """
    edges: list[ConceptEdge] = []
    scheduled = landing != host_id
    for finding in findings:
        edges.append(
            ConceptEdge(
                rel_type="CAN_ESCAPE_TO",
                target_native_id=landing,
                target_concept_type=ConceptType.RUNTIME_BINDING,
                props={
                    "target": "node" if scheduled else "node/host",
                    "severity": finding["severity"],
                    "mechanism": finding["kind"],
                    "description": finding["description"],
                },
                confidence=ConfidenceType.EXPLICIT,
            )
        )
        if scheduled:
            edges.append(
                ConceptEdge(
                    rel_type="CAN_ESCAPE_TO",
                    target_native_id=host_id,
                    target_concept_type=ConceptType.RUNTIME_BINDING,
                    props={
                        "target": "node/host",
                        "severity": finding["severity"],
                        "mechanism": finding["kind"],
                        "description": finding["description"],
                    },
                    confidence=ConfidenceType.EXPLICIT,
                )
            )
    return edges
