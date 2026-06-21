from __future__ import annotations

from typing import Any

from samoyed.graph.model import GraphSnapshot
from samoyed.graph.neighbors import get_neighbors
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import find_attack_paths, get_blast_radius


def run_graph_query(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    mode: str = "paths",
    target_concept: str | None = None,
    target_resource_type: str | None = None,
    end_node_id: str | None = None,
    end_id_contains: str | None = None,
    rel_types: list[str] | None = None,
    max_depth: int = 6,
    max_paths: int = 20,
) -> dict[str, Any]:
    rel_filter = set(rel_types) if rel_types else None

    if mode == "neighbors":
        nodes = get_neighbors(graph, start_node_id, direction="both")
        if rel_filter:
            nodes = [n for n in nodes if n["rel_type"] in rel_filter]
        return {"mode": mode, "start": start_node_id, "nodes": nodes, "paths": []}

    if mode == "blast":
        paths = get_blast_radius(graph, start_node_id=start_node_id, max_depth=max_depth)
        if rel_filter:
            paths = [_filter_path_rels(p, rel_filter) for p in paths]
            paths = [p for p in paths if p is not None]
        return {"mode": mode, "start": start_node_id, "paths": [_serialize(p) for p in paths[:max_paths]]}

    paths = find_attack_paths(
        graph,
        start_node_id=start_node_id,
        target_concept=target_concept or None,
        target_resource_type=target_resource_type or None,
        end_node_id=end_node_id,
        end_id_contains=end_id_contains,
        rel_types=rel_filter,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    return {"mode": mode, "start": start_node_id, "paths": [_serialize(p) for p in paths]}


def _filter_path_rels(path: PathResult, rel_filter: set[str]) -> PathResult | None:
    if all(step.rel_type in rel_filter for step in path.steps):
        return path
    return None


def _serialize(path: PathResult) -> dict[str, Any]:
    return {
        "path_id": path.path_id,
        "score": path.score,
        "node_ids": path.node_ids,
        "target_match": path.target_match,
        "steps": [
            {
                "step": s.step_index,
                "src": s.src_id,
                "rel": s.rel_type,
                "dst": s.dst_id,
                "evidence": s.evidence,
            }
            for s in path.steps
        ],
    }
