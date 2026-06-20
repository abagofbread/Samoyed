from __future__ import annotations

import hashlib
from collections import deque

from samoyed.cloud.concepts import TRAVERSABLE_REL_TYPES
from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.models import PathResult, PathStep
from samoyed.path_engine.scoring import score_path


def _matches_target(node_props: dict, target_concept: str | None, target_resource_type: str | None) -> bool:
    if target_concept and node_props.get("concept_type") == target_concept:
        return True
    if target_resource_type and node_props.get("resource_type") == target_resource_type:
        return True
    return False


def find_attack_paths(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    target_concept: str | None = None,
    target_resource_type: str | None = None,
    max_depth: int = 6,
    max_paths: int = 10,
) -> list[PathResult]:
    if start_node_id not in graph.nodes:
        return []

    results: list[PathResult] = []
    queue: deque[tuple[str, int, list[str], list[tuple[str, str, dict]]]] = deque()
    queue.append((start_node_id, 0, [start_node_id], []))

    while queue and len(results) < max_paths:
        current, depth, node_seq, edge_seq = queue.popleft()
        if depth >= max_depth:
            continue

        for dst_id, rel_type, props in graph.adjacency.get(current, []):
            if rel_type not in TRAVERSABLE_REL_TYPES:
                continue
            if dst_id in node_seq:
                continue

            next_nodes = node_seq + [dst_id]
            next_edges = edge_seq + [(current, rel_type, dst_id, props)]
            next_depth = depth + 1

            dst_node = graph.nodes.get(dst_id)
            dst_props_dict = dst_node.props if dst_node else {}

            if _matches_target(dst_props_dict, target_concept, target_resource_type):
                rel_types = [e[1] for e in next_edges]
                edge_props = [e[3] for e in next_edges]
                score = score_path(rel_types, edge_props)
                steps = [
                    PathStep(
                        step_index=i,
                        src_id=e[0],
                        rel_type=e[1],
                        dst_id=e[2],
                        evidence=e[3],
                        confidence=e[3].get("confidence", "explicit"),
                    )
                    for i, e in enumerate(next_edges)
                ]
                path_key = "->".join(next_nodes)
                results.append(
                    PathResult(
                        path_id=hashlib.sha256(path_key.encode()).hexdigest()[:12],
                        node_ids=next_nodes,
                        score=score,
                        steps=steps,
                        target_match={
                            "node_id": dst_id,
                            "concept_type": dst_props_dict.get("concept_type"),
                            "resource_type": dst_props_dict.get("resource_type"),
                        },
                    )
                )

            if next_depth < max_depth:
                queue.append((dst_id, next_depth, next_nodes, next_edges))

    results.sort(key=lambda p: p.score, reverse=True)
    return results[:max_paths]


def get_blast_radius(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    target_concepts: list[str] | None = None,
    max_depth: int = 6,
) -> list[PathResult]:
    target_concepts = target_concepts or ["AttackOutcome", "SecretStore", "DataStore", "Identity"]
    all_paths: list[PathResult] = []
    seen: set[str] = set()
    for concept in target_concepts:
        for path in find_attack_paths(
            graph,
            start_node_id=start_node_id,
            target_concept=concept,
            max_depth=max_depth,
            max_paths=5,
        ):
            if path.path_id not in seen:
                seen.add(path.path_id)
                all_paths.append(path)
    all_paths.sort(key=lambda p: p.score, reverse=True)
    return all_paths
