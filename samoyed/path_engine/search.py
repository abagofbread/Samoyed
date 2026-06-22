from __future__ import annotations

import hashlib
from collections import deque
from typing import Literal

from samoyed.cloud.concepts import TRAVERSABLE_REL_TYPES
from samoyed.graph.markings import find_compromised_nodes, find_high_value_nodes, is_high_value
from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.models import PathResult, PathStep
from samoyed.path_engine.scoring import score_path

Direction = Literal["out", "in", "both"]


def _matches_target(node_props: dict, target_concept: str | None, target_resource_type: str | None) -> bool:
    if target_concept and node_props.get("concept_type") == target_concept:
        return True
    if target_resource_type and node_props.get("resource_type") == target_resource_type:
        return True
    return False


def _matches_custom_target(
    node_id: str,
    node_props: dict,
    *,
    target_concept: str | None,
    target_resource_type: str | None,
    end_node_id: str | None,
    end_id_contains: str | None,
) -> bool:
    if end_node_id and node_id == end_node_id:
        return True
    if end_id_contains:
        haystack = " ".join(
            str(node_props.get(key) or "")
            for key in ("native_id", "arn", "display_name", "name", "bucket_name")
        ) + " " + node_id
        if end_id_contains.lower() in haystack.lower():
            return True
    if target_concept in {"high_value", "HighValue", "crown_jewel", "crown-jewel"}:
        return is_high_value(node_props)
    if not target_concept and not target_resource_type and not end_node_id and not end_id_contains:
        return False
    return _matches_target(node_props, target_concept, target_resource_type)


def _iter_traversal_steps(
    graph: GraphSnapshot,
    node_id: str,
    *,
    direction: Direction,
    allowed_rels: set[str],
) -> list[tuple[str, str, str, dict]]:
    """Yield (next_node_id, step_src, step_rel, step_dst, props) for each traversable step."""
    steps: list[tuple[str, str, str, dict]] = []
    if direction in {"out", "both"}:
        for dst_id, rel_type, props in graph.adjacency.get(node_id, []):
            if rel_type in allowed_rels:
                steps.append((dst_id, node_id, rel_type, dst_id, props))
    if direction in {"in", "both"}:
        for edge in graph.edges:
            if edge.dst_id != node_id or edge.rel_type not in allowed_rels:
                continue
            steps.append((edge.src_id, edge.src_id, edge.rel_type, edge.dst_id, edge.props))
    return steps


def _path_result_from_edges(
    node_seq: list[str],
    edge_seq: list[tuple[str, str, str, dict]],
    *,
    endpoint_id: str,
    endpoint_props: dict,
) -> PathResult:
    path_rel_types = [e[1] for e in edge_seq]
    edge_props = [e[3] for e in edge_seq]
    score = score_path(path_rel_types, edge_props)
    steps = [
        PathStep(
            step_index=i,
            src_id=e[0],
            rel_type=e[1],
            dst_id=e[2],
            evidence=e[3],
            confidence=e[3].get("confidence", "explicit"),
        )
        for i, e in enumerate(edge_seq)
    ]
    path_key = "->".join(node_seq)
    return PathResult(
        path_id=hashlib.sha256(path_key.encode()).hexdigest()[:12],
        node_ids=node_seq,
        score=score,
        steps=steps,
        target_match={
            "node_id": endpoint_id,
            "concept_type": endpoint_props.get("concept_type"),
            "resource_type": endpoint_props.get("resource_type"),
        },
    )


def find_attack_paths(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    target_concept: str | None = None,
    target_resource_type: str | None = None,
    end_node_id: str | None = None,
    end_id_contains: str | None = None,
    rel_types: set[str] | None = None,
    direction: Direction = "out",
    max_depth: int = 6,
    max_paths: int = 10,
) -> list[PathResult]:
    if start_node_id not in graph.nodes:
        return []

    allowed_rels = rel_types or TRAVERSABLE_REL_TYPES
    results: list[PathResult] = []
    queue: deque[tuple[str, int, list[str], list[tuple[str, str, str, dict]]]] = deque()
    queue.append((start_node_id, 0, [start_node_id], []))

    while queue and len(results) < max_paths:
        current, depth, node_seq, edge_seq = queue.popleft()
        if depth >= max_depth:
            continue

        for next_id, step_src, rel_type, step_dst, props in _iter_traversal_steps(
            graph,
            current,
            direction=direction,
            allowed_rels=allowed_rels,
        ):
            if next_id in node_seq:
                continue

            next_nodes = node_seq + [next_id]
            next_edges = edge_seq + [(step_src, rel_type, step_dst, props)]
            next_depth = depth + 1

            dst_node = graph.nodes.get(next_id)
            dst_props_dict = dst_node.props if dst_node else {}

            if _matches_custom_target(
                next_id,
                dst_props_dict,
                target_concept=target_concept,
                target_resource_type=target_resource_type,
                end_node_id=end_node_id,
                end_id_contains=end_id_contains,
            ):
                results.append(
                    _path_result_from_edges(
                        next_nodes,
                        next_edges,
                        endpoint_id=next_id,
                        endpoint_props=dst_props_dict,
                    )
                )

            if next_depth < max_depth:
                queue.append((next_id, next_depth, next_nodes, next_edges))

    results.sort(key=lambda p: p.score, reverse=True)
    return results[:max_paths]


def find_forward_reachability(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    rel_types: set[str] | None = None,
    max_depth: int = 6,
    max_paths: int = 20,
) -> list[PathResult]:
    """Shortest forward-only path to each node reachable from the start."""
    if start_node_id not in graph.nodes:
        return []

    allowed_rels = rel_types or TRAVERSABLE_REL_TYPES
    results: list[PathResult] = []
    queue: deque[tuple[str, int, list[str], list[tuple[str, str, str, dict]]]] = deque()
    queue.append((start_node_id, 0, [start_node_id], []))
    visited: set[str] = {start_node_id}

    while queue and len(results) < max_paths:
        current, depth, node_seq, edge_seq = queue.popleft()
        if depth >= max_depth:
            continue

        for next_id, step_src, rel_type, step_dst, props in _iter_traversal_steps(
            graph,
            current,
            direction="out",
            allowed_rels=allowed_rels,
        ):
            if next_id in visited:
                continue
            visited.add(next_id)

            next_nodes = node_seq + [next_id]
            next_edges = edge_seq + [(step_src, rel_type, step_dst, props)]
            next_depth = depth + 1

            endpoint = graph.nodes.get(next_id)
            endpoint_props = endpoint.props if endpoint else {}
            results.append(
                _path_result_from_edges(
                    next_nodes,
                    next_edges,
                    endpoint_id=next_id,
                    endpoint_props=endpoint_props,
                )
            )

            if next_depth < max_depth:
                queue.append((next_id, next_depth, next_nodes, next_edges))

    def _endpoint_high_value(path: PathResult) -> bool:
        node_id = path.target_match.get("node_id")
        node = graph.nodes.get(node_id) if node_id else None
        return is_high_value(node.props) if node else False

    results.sort(key=lambda p: (_endpoint_high_value(p), p.score, len(p.steps)), reverse=True)
    return results[:max_paths]


def get_blast_radius(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    max_depth: int = 6,
    max_paths: int = 20,
    rel_types: set[str] | None = None,
) -> list[PathResult]:
    """All forward reachability from start — one shortest path per reachable node."""
    return find_forward_reachability(
        graph,
        start_node_id=start_node_id,
        rel_types=rel_types,
        max_depth=max_depth,
        max_paths=max_paths,
    )


def find_attack_paths_from_sources(
    graph: GraphSnapshot,
    *,
    start_node_ids: list[str],
    target_concept: str | None = None,
    target_resource_type: str | None = None,
    end_node_id: str | None = None,
    end_id_contains: str | None = None,
    end_node_ids: list[str] | None = None,
    rel_types: set[str] | None = None,
    direction: Direction = "out",
    max_depth: int = 6,
    max_paths: int = 20,
) -> list[PathResult]:
    """Run path search from multiple start nodes; dedupe and rank combined results."""
    if not start_node_ids:
        return []

    seen: set[str] = set()
    combined: list[PathResult] = []
    per_start = max(1, max_paths // len(start_node_ids))

    for start_id in start_node_ids:
        if start_id not in graph.nodes:
            continue
        targets = end_node_ids or ([end_node_id] if end_node_id else [None])
        for target in targets:
            paths = find_attack_paths(
                graph,
                start_node_id=start_id,
                target_concept=target_concept,
                target_resource_type=target_resource_type,
                end_node_id=target,
                end_id_contains=end_id_contains,
                rel_types=rel_types,
                direction=direction,
                max_depth=max_depth,
                max_paths=per_start,
            )
            for path in paths:
                if path.path_id in seen:
                    continue
                seen.add(path.path_id)
                combined.append(path)

    combined.sort(key=lambda p: p.score, reverse=True)
    return combined[:max_paths]


def get_blast_radius_multi(
    graph: GraphSnapshot,
    *,
    start_node_ids: list[str],
    max_depth: int = 6,
    max_paths: int = 30,
    rel_types: set[str] | None = None,
) -> list[PathResult]:
    seen: set[str] = set()
    combined: list[PathResult] = []
    per_start = max(1, max_paths // max(len(start_node_ids), 1))
    for start_id in start_node_ids:
        for path in get_blast_radius(
            graph,
            start_node_id=start_id,
            max_depth=max_depth,
            max_paths=per_start,
            rel_types=rel_types,
        ):
            if path.path_id in seen:
                continue
            seen.add(path.path_id)
            combined.append(path)
            if len(combined) >= max_paths:
                break
        if len(combined) >= max_paths:
            break
    combined.sort(key=lambda p: p.score, reverse=True)
    return combined[:max_paths]


def find_compromised_to_high_value_paths(
    graph: GraphSnapshot,
    *,
    max_depth: int = 6,
    max_paths: int = 30,
) -> list[PathResult]:
    """All attack paths from any compromised node to any analyst-marked high-value node."""
    starts = find_compromised_nodes(graph)
    targets = find_high_value_nodes(graph)
    if not starts or not targets:
        return []
    return find_attack_paths_from_sources(
        graph,
        start_node_ids=starts,
        end_node_ids=targets,
        max_depth=max_depth,
        max_paths=max_paths,
    )


def find_paths_to_high_value_nodes(
    graph: GraphSnapshot,
    *,
    start_node_ids: list[str] | None = None,
    max_depth: int = 6,
    max_paths: int = 30,
) -> list[PathResult]:
    """Paths from given starts (default: all compromised) to each high-value node."""
    starts = start_node_ids or find_compromised_nodes(graph)
    targets = find_high_value_nodes(graph)
    if not starts or not targets:
        return []
    return find_attack_paths_from_sources(
        graph,
        start_node_ids=starts,
        end_node_ids=targets,
        max_depth=max_depth,
        max_paths=max_paths,
    )
