from __future__ import annotations

from typing import Any

from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot

POD_CREATE_ACTIONS = frozenset({"rbac:pods:create"})
POD_EXEC_ACTIONS = frozenset({"rbac:pods:exec"})
WORKLOAD_WILDCARD = "kubernetes:workload:*"


def enrich_k8s_deploy_pivot(builder: GraphBuilder) -> dict[str, int]:
    """
    Wire K8s workload-control pivots:
    - pods/create (or update) → deploy pod as any SA in bound namespace(s)
    - pods/exec → exec into running pods and inherit their service accounts
    """
    graph = builder.snapshot
    sas_by_ns = _service_accounts_by_namespace(graph)
    pods_by_ns = _pods_by_namespace(graph)
    if not sas_by_ns and not pods_by_ns:
        return {"deploy_exec_as": 0, "exec_into_pods": 0, "exec_exec_as": 0}

    deploy_exec_as = 0
    exec_into_pods = 0
    exec_exec_as = 0

    for edge in list(graph.edges):
        if edge.rel_type != "CONTROLS":
            continue
        dst = graph.nodes.get(edge.dst_id)
        if not dst:
            continue
        if not _is_workload_control_target(dst):
            continue

        action = edge.props.get("action")
        actions = {action} if action else set()
        if not actions:
            actions = _actions_from_rbac_rules(edge.props.get("rbac_rule") or [])

        namespaces = _namespaces_for_control(edge.props.get("namespace"), sas_by_ns, pods_by_ns)
        src_id = edge.src_id

        if actions & POD_CREATE_ACTIONS:
            for ns in namespaces:
                for sa_id in sas_by_ns.get(ns, []):
                    if _add_pivot_edge(
                        builder,
                        graph,
                        src_id=src_id,
                        rel_type="EXECUTES_AS",
                        dst_id=sa_id,
                        mechanism="k8s-pod-deploy",
                        action="rbac:pods:create",
                        namespace=ns,
                        confidence="wildcard",
                    ):
                        deploy_exec_as += 1

        if actions & POD_EXEC_ACTIONS:
            for ns in namespaces:
                for pod_id, sa_id in pods_by_ns.get(ns, []):
                    if _add_pivot_edge(
                        builder,
                        graph,
                        src_id=src_id,
                        rel_type="CONTROLS",
                        dst_id=pod_id,
                        mechanism="k8s-pods-exec",
                        action="rbac:pods:exec",
                        namespace=ns,
                        confidence="explicit",
                    ):
                        exec_into_pods += 1
                    if sa_id and _add_pivot_edge(
                        builder,
                        graph,
                        src_id=src_id,
                        rel_type="EXECUTES_AS",
                        dst_id=sa_id,
                        mechanism="k8s-pods-exec",
                        action="rbac:pods:exec",
                        namespace=ns,
                        confidence="explicit",
                        via_pod=pod_id,
                    ):
                        exec_exec_as += 1

    return {
        "deploy_exec_as": deploy_exec_as,
        "exec_into_pods": exec_into_pods,
        "exec_exec_as": exec_exec_as,
    }


def _service_accounts_by_namespace(graph: GraphSnapshot) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for node_id, node in graph.nodes.items():
        native = str(node.props.get("native_id") or "")
        if node.props.get("native_kind") == "ServiceAccount" or native.startswith("kubernetes:serviceaccount:"):
            ns = node.props.get("namespace") or _namespace_from_native(native, prefix="kubernetes:serviceaccount:")
            if ns:
                out.setdefault(str(ns), []).append(node_id)
    return out


def _pods_by_namespace(graph: GraphSnapshot) -> dict[str, list[tuple[str, str | None]]]:
    out: dict[str, list[tuple[str, str | None]]] = {}
    for node_id, node in graph.nodes.items():
        native = str(node.props.get("native_id") or "")
        is_pod = node.props.get("native_kind") == "Pod" or (
            node.props.get("concept_type") == "Workload" and native.startswith("kubernetes:pod:")
        )
        if not is_pod:
            continue
        ns = node.props.get("namespace") or _namespace_from_native(native, prefix="kubernetes:pod:")
        if not ns:
            continue
        sa_name = node.props.get("service_account") or "default"
        sa_native = f"kubernetes:serviceaccount:{ns}:{sa_name}"
        sa_id = _node_id_for_native(graph, sa_native)
        out.setdefault(str(ns), []).append((node_id, sa_id))
    return out


def _namespace_from_native(native_id: str, *, prefix: str) -> str | None:
    if not native_id.startswith(prefix):
        return None
    parts = native_id[len(prefix) :].split(":", 1)
    return parts[0] if parts else None


def _node_id_for_native(graph: GraphSnapshot, native_id: str) -> str | None:
    for node_id, node in graph.nodes.items():
        if node.props.get("native_id") == native_id:
            return node_id
    return None


def _is_workload_control_target(node: Any) -> bool:
    native = str(node.props.get("native_id") or "")
    if native == WORKLOAD_WILDCARD or native.endswith(":workload:*"):
        return True
    if node.props.get("concept_type") == "Workload" and native.endswith("*"):
        return True
    return False


def _namespaces_for_control(
    namespace: str | None,
    sas_by_ns: dict[str, list[str]],
    pods_by_ns: dict[str, list[tuple[str, str | None]]],
) -> list[str]:
    if namespace:
        return [namespace]
    keys = set(sas_by_ns) | set(pods_by_ns)
    return sorted(keys)


def _actions_from_rbac_rules(rules: list[dict[str, Any]]) -> set[str]:
    from samoyed.enumerators.k8s.helpers import rule_grants

    actions: set[str] = set()
    for _rel, _concept, action in rule_grants(rules):
        if action:
            actions.add(action)
    return actions


def _add_pivot_edge(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    src_id: str,
    rel_type: str,
    dst_id: str,
    mechanism: str,
    action: str,
    namespace: str,
    confidence: str,
    via_pod: str | None = None,
) -> bool:
    if _has_edge(graph, src_id, rel_type, dst_id):
        return False
    props = enrichment_edge_props(
        source="k8s-deploy-pivot",
        mechanism=mechanism,
        action=action,
        namespace=namespace,
        confidence=confidence,
    )
    if via_pod:
        props["via_pod"] = via_pod
    builder.add_edge(src_id=src_id, rel_type=rel_type, dst_id=dst_id, props=props)
    return True


def _has_edge(graph: GraphSnapshot, src_id: str, rel_type: str, dst_id: str) -> bool:
    for edge in graph.adjacency.get(src_id, []):
        if edge[0] == dst_id and edge[1] == rel_type:
            return True
    return False
