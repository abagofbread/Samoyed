from __future__ import annotations

from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import find_attack_paths


class CanReachOtherAccountsScenario:
    """Paths from a start that cross peering into another account or GCP project."""

    name = "can-reach-other-accounts"

    def run(self, graph: GraphSnapshot, start_node_id: str) -> list[PathResult]:
        paths = find_attack_paths(
            graph,
            start_node_id=start_node_id,
            target_concept="ScopeBoundary",
            max_depth=8,
        )
        crossing = [p for p in paths if _path_crosses_account(graph, p)]
        if crossing:
            return crossing

        runtime_paths = find_attack_paths(
            graph,
            start_node_id=start_node_id,
            target_concept="RuntimeBinding",
            max_depth=8,
        )
        return [p for p in runtime_paths if _path_crosses_account(graph, p)]


def _path_crosses_account(graph: GraphSnapshot, path: PathResult) -> bool:
    for step in path.steps:
        if step.rel_type in {"VPC_PEERS", "BRIDGES_TO"}:
            return True
        evidence = step.evidence or {}
        if evidence.get("remote_account_id") or evidence.get("remote_project_id") or evidence.get("boundary_crossing"):
            return True
    end_id = path.node_ids[-1] if path.node_ids else None
    if not end_id:
        return False
    end = graph.nodes.get(end_id)
    if not end:
        return False
    props = end.props or {}
    if props.get("is_cross_account_boundary"):
        return True
    native = str(props.get("native_id") or "")
    return native.startswith(("aws:account:", "gcp:project:")) and props.get("concept_type") == "ScopeBoundary"
