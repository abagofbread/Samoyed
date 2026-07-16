from __future__ import annotations

import hashlib
from collections import deque
from typing import Literal

from samoyed.cloud.concepts import TRAVERSABLE_REL_TYPES
from samoyed.attack.outcomes import (
    is_attack_outcome_edge,
    matches_attack_outcome_target,
    virtual_outcome_target,
)
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


def _resolve_path_endpoint(
    node_id: str,
    node_props: dict,
    *,
    rel_type: str,
    edge_props: dict,
    target_concept: str | None,
    target_resource_type: str | None,
    end_node_id: str | None,
    end_id_contains: str | None,
) -> dict | None:
    if _matches_custom_target(
        node_id,
        node_props,
        target_concept=target_concept,
        target_resource_type=target_resource_type,
        end_node_id=end_node_id,
        end_id_contains=end_id_contains,
    ):
        return {
            "node_id": node_id,
            "concept_type": node_props.get("concept_type"),
            "resource_type": node_props.get("resource_type"),
        }
    if matches_attack_outcome_target(
        rel_type,
        edge_props,
        target_concept=target_concept,
        target_resource_type=target_resource_type,
    ) and not end_node_id and not end_id_contains:
        return virtual_outcome_target(edge_props, node_id)
    return None


def _outcome_path_key(node_id: str, edge_props: dict) -> str:
    return f"outcome:{node_id}:{edge_props.get('pattern_id') or edge_props.get('attack_outcome')}"


def _iter_traversal_steps(
    graph: GraphSnapshot,
    node_id: str,
    *,
    direction: Direction,
    allowed_rels: set[str],
) -> list[tuple[str, str, str, str, dict]]:
    """Yield (next_node_id, step_src, step_rel, step_dst, props) for each traversable step."""
    steps: list[tuple[str, str, str, str, dict]] = []
    if direction in {"out", "both"}:
        for dst_id, rel_type, props in graph.adjacency.get(node_id, []):
            if rel_type in allowed_rels:
                steps.append((dst_id, node_id, rel_type, dst_id, props))
    if direction in {"in", "both"}:
        for edge in graph.edges:
            if edge.dst_id != node_id or edge.rel_type not in allowed_rels:
                continue
            steps.append((edge.src_id, edge.src_id, edge.rel_type, edge.dst_id, edge.props))
    steps.sort(key=_traversal_step_priority)
    return steps


def _traversal_step_priority(step: tuple[str, str, str, str, dict]) -> tuple:
    """Prefer PassRole / capability→resource edges when multiple edges share a destination."""
    _next, _src, rel, _dst, props = step
    passrole = 0 if (
        rel == "CAN_PRIVESC_TO"
        and "PassRole" in str(props.get("pattern_name") or props.get("pattern_id") or "")
    ) else 1
    capability = 0 if rel in _CAPABILITY_BLAST_RELS else 1
    return (passrole, capability, rel)

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
            **{
                key: endpoint_props[key]
                for key in ("outcome_type", "outcome_display", "virtual")
                if key in endpoint_props
            },
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
            privesc_outcome = is_attack_outcome_edge(rel_type, props) and next_id == current
            if next_id in node_seq and not privesc_outcome:
                continue

            next_nodes = node_seq if privesc_outcome else node_seq + [next_id]
            next_edges = edge_seq + [(step_src, rel_type, step_dst, props)]
            next_depth = depth + 1

            dst_node = graph.nodes.get(next_id)
            dst_props_dict = dst_node.props if dst_node else {}

            endpoint = _resolve_path_endpoint(
                next_id,
                dst_props_dict,
                rel_type=rel_type,
                edge_props=props,
                target_concept=target_concept,
                target_resource_type=target_resource_type,
                end_node_id=end_node_id,
                end_id_contains=end_id_contains,
            )
            if endpoint:
                results.append(
                    _path_result_from_edges(
                        next_nodes,
                        next_edges,
                        endpoint_id=next_id,
                        endpoint_props=endpoint,
                    )
                )

            if privesc_outcome:
                continue

            if next_depth < max_depth:
                queue.append((next_id, next_depth, next_nodes, next_edges))

    results.sort(key=lambda p: p.score, reverse=True)
    return results[:max_paths]


_CAPABILITY_BLAST_RELS = frozenset({"READS", "WRITES", "DELETES", "CONTROLS", "EXECUTES"})
_RESOURCEISH_CONCEPTS = frozenset(
    {
        "DataStore",
        "SecretStore",
        "RegistryStore",
        "RuntimeBinding",
        "Workload",
        "NetworkExposure",
        "AttackOutcome",
    }
)


def _is_aws_service_linked_role(node_id: str, props: dict) -> bool:
    hay = f"{node_id} {props.get('arn', '')} {props.get('native_id', '')}"
    return "/aws-service-role/" in hay or ":role/aws-service-role/" in hay


def _blast_rank_key(graph: GraphSnapshot, path: PathResult) -> tuple:
    """Rank blast hits: concrete resource impact + FEEDS influence first."""
    node_id = path.target_match.get("node_id") or ""
    node = graph.nodes.get(node_id)
    props = node.props if node else {}
    last = path.steps[-1] if path.steps else None
    last_rel = last.rel_type if last else ""
    last_props = last.evidence if last else {}

    hvt = 1 if is_high_value(props) else 0
    # AttackOutcome nodes are UI-suppressed and crowd out real impact — demote hard.
    outcome = -1 if props.get("concept_type") == "AttackOutcome" or props.get("virtual") else 0

    concrete = 0
    native = str(props.get("native_id") or node_id)
    if "*" not in native and not native.endswith(":*"):
        if props.get("concept_type") in _RESOURCEISH_CONCEPTS or node_id.startswith("Resource:"):
            concrete = 2
        elif props.get("concept_type") == "Workload":
            concrete = 2

    feeds_hit = 1 if last_rel == "FEEDS" else 0

    resource_hit = 0
    if last_rel in _CAPABILITY_BLAST_RELS:
        ctype = props.get("concept_type") or ""
        if ctype in _RESOURCEISH_CONCEPTS or node_id.startswith("Resource:"):
            resource_hit = 2 if concrete else 1
        elif ctype == "Workload":
            resource_hit = 2
        elif ctype != "Identity":
            resource_hit = 1
    passrole = 1 if (
        last_rel == "CAN_PRIVESC_TO"
        and "PassRole" in str(last_props.get("pattern_name") or last_props.get("pattern_id") or "")
    ) else 0
    service_noise = 1 if _is_aws_service_linked_role(node_id, props) else 0
    stub_noise = 0
    if ("*" in native or native.endswith(":*")) and props.get("concept_type") in _RESOURCEISH_CONCEPTS:
        # ControLS/WRITES on * is real influence ("can create/poison any X"); demote only READS stubs.
        if last_rel == "READS":
            stub_noise = 1
    # Higher tuple sorts first when reverse=True — put noise last via negative.
    return (
        concrete,
        feeds_hit,
        hvt,
        resource_hit,
        passrole,
        outcome,
        -service_noise,
        -stub_noise,
        path.score,
        -len(path.steps),
    )


def find_forward_reachability(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    rel_types: set[str] | None = None,
    max_depth: int = 6,
    max_paths: int = 20,
) -> list[PathResult]:
    """Shortest forward-only path to each node reachable from the start.

    Completes BFS before truncating so capability→resource hits aren't dropped
    when many CAN_PRIVESC_TO edges appear first in adjacency.
    """
    if start_node_id not in graph.nodes:
        return []

    allowed_rels = rel_types or TRAVERSABLE_REL_TYPES
    results: list[PathResult] = []
    queue: deque[tuple[str, int, list[str], list[tuple[str, str, str, dict]]]] = deque()
    queue.append((start_node_id, 0, [start_node_id], []))
    visited: set[str] = {start_node_id}
    visited_outcomes: set[str] = set()
    # Soft cap so dense graphs stay bounded; still far above typical max_paths.
    max_visit = max(max_paths * 40, 400)

    while queue and len(visited) <= max_visit:
        current, depth, node_seq, edge_seq = queue.popleft()
        if depth >= max_depth:
            continue

        for next_id, step_src, rel_type, step_dst, props in _iter_traversal_steps(
            graph,
            current,
            direction="out",
            allowed_rels=allowed_rels,
        ):
            if is_attack_outcome_edge(rel_type, props) and next_id == current:
                outcome_key = _outcome_path_key(current, props)
                if outcome_key in visited_outcomes:
                    continue
                visited_outcomes.add(outcome_key)
                next_edges = edge_seq + [(step_src, rel_type, step_dst, props)]
                results.append(
                    _path_result_from_edges(
                        node_seq,
                        next_edges,
                        endpoint_id=current,
                        endpoint_props=virtual_outcome_target(props, current),
                    )
                )
                continue

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

            if next_depth < max_depth and len(visited) < max_visit:
                queue.append((next_id, next_depth, next_nodes, next_edges))

    results.sort(key=lambda p: _blast_rank_key(graph, p), reverse=True)
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
