from __future__ import annotations

from typing import Any

from samoyed.graph.model import GraphSnapshot
from samoyed.graph.neighbors import get_neighbors
from samoyed.path_engine.models import PathResult
from samoyed.graph.markings import DEFAULT_BLAST_CONCEPTS, find_high_value_nodes
from samoyed.path_engine.search import find_attack_paths, find_attack_paths_from_sources, get_blast_radius


def _normalize_path_targets(
    mode: str,
    *,
    target_concept: str | None,
    target_resource_type: str | None,
    end_node_id: str | None,
    end_id_contains: str | None,
) -> str | None:
    if mode != "paths":
        return target_concept
    if target_concept or target_resource_type or end_node_id or end_id_contains:
        return target_concept
    return None


def _has_explicit_path_target(
    *,
    target_concept: str | None,
    target_resource_type: str | None,
    end_node_id: str | None,
    end_id_contains: str | None,
) -> bool:
    return bool(target_concept or target_resource_type or end_node_id or end_id_contains)


def _default_attack_paths(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    rel_filter: set[str] | None,
    max_depth: int,
    max_paths: int,
    exclude_node_ids: set[str] | None = None,
) -> list[PathResult]:
    """Paths to analyst-marked high-value nodes, or crown-jewel concept types."""
    marked = [n for n in find_high_value_nodes(graph) if not exclude_node_ids or n not in exclude_node_ids]
    if marked:
        return find_attack_paths_from_sources(
            graph,
            start_node_ids=[start_node_id],
            end_node_ids=marked,
            rel_types=rel_filter,
            direction="both",
            max_depth=max_depth,
            max_paths=max_paths,
            exclude_node_ids=exclude_node_ids,
        )

    seen: set[str] = set()
    combined: list[PathResult] = []
    per_concept = max(1, max_paths // len(DEFAULT_BLAST_CONCEPTS))
    for concept in DEFAULT_BLAST_CONCEPTS:
        for path in find_attack_paths(
            graph,
            start_node_id=start_node_id,
            target_concept=concept,
            rel_types=rel_filter,
            direction="both",
            max_depth=max_depth,
            max_paths=per_concept,
            exclude_node_ids=exclude_node_ids,
        ):
            if path.path_id in seen:
                continue
            seen.add(path.path_id)
            combined.append(path)
    combined.sort(key=lambda p: p.score, reverse=True)
    return combined[:max_paths]


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
    exclude_node_ids: list[str] | None = None,
) -> dict[str, Any]:
    rel_filter = set(rel_types) if rel_types else None
    excluded = set(exclude_node_ids or ())
    target_concept = _normalize_path_targets(
        mode,
        target_concept=target_concept,
        target_resource_type=target_resource_type,
        end_node_id=end_node_id,
        end_id_contains=end_id_contains,
    )
    explicit_target = _has_explicit_path_target(
        target_concept=target_concept,
        target_resource_type=target_resource_type,
        end_node_id=end_node_id,
        end_id_contains=end_id_contains,
    )

    if mode == "neighbors":
        nodes = get_neighbors(graph, start_node_id, direction="both")
        if rel_filter:
            nodes = [n for n in nodes if n["rel_type"] in rel_filter]
        if excluded:
            nodes = [n for n in nodes if n["node_id"] not in excluded]
        return {"mode": mode, "start": start_node_id, "nodes": nodes, "paths": []}

    if mode == "blast":
        paths = get_blast_radius(
            graph,
            start_node_id=start_node_id,
            max_depth=max_depth,
            max_paths=max_paths,
            rel_types=rel_filter,
            exclude_node_ids=excluded or None,
        )
        return {"mode": mode, "start": start_node_id, "paths": [_serialize(p) for p in paths]}

    if mode == "paths" and not explicit_target:
        paths = _default_attack_paths(
            graph,
            start_node_id=start_node_id,
            rel_filter=rel_filter,
            max_depth=max_depth,
            max_paths=max_paths,
            exclude_node_ids=excluded or None,
        )
        return {"mode": mode, "start": start_node_id, "paths": [_serialize(p) for p in paths]}

    paths = find_attack_paths(
        graph,
        start_node_id=start_node_id,
        target_concept=target_concept or None,
        target_resource_type=target_resource_type or None,
        end_node_id=end_node_id,
        end_id_contains=end_id_contains,
        rel_types=rel_filter,
        direction="both",
        max_depth=max_depth,
        max_paths=max_paths,
        exclude_node_ids=excluded or None,
    )
    return {"mode": mode, "start": start_node_id, "paths": [_serialize(p) for p in paths]}


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


def serialize_paths(paths: list[PathResult]) -> list[dict[str, Any]]:
    return [_serialize(p) for p in paths]
