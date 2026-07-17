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
    priority: str = "path",
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
    key = _blast_traversal_step_priority if priority == "blast" else _path_traversal_step_priority
    steps.sort(key=key)
    return steps


_IDENTITY_CHAIN_RELS = frozenset(
    {
        "EXECUTES_AS",
        "CAN_ASSUME_ROLE",
        "PROJECTS_TO",
        "LOGGED_IN_AS",
        "STORES_CREDS_FOR",
        "CAN_STEAL_CREDS_FROM",
        "HAS_MATERIAL",
        "UNLOCKS",
    }
)


def _path_traversal_step_priority(step: tuple[str, str, str, str, dict]) -> tuple:
    """Prefer identity/trust chain hops for attack-path search (STS / assume-role stories)."""
    _next, _src, rel, _dst, props = step
    passrole = 0 if (
        rel == "CAN_PRIVESC_TO"
        and "PassRole" in str(props.get("pattern_name") or props.get("pattern_id") or "")
    ) else 1
    identity = 0 if rel in _IDENTITY_CHAIN_RELS else 1
    escape_last = 1 if rel in {"CAN_ESCAPE_TO", "HAS_ESCAPE_SURFACE"} else 0
    return (passrole, identity, escape_last, rel)


def _blast_traversal_step_priority(step: tuple[str, str, str, str, dict]) -> tuple:
    """Prefer write-control influence over READS when expanding blast radius."""
    _next, _src, rel, _dst, props = step
    passrole = 0 if (
        rel == "CAN_PRIVESC_TO"
        and "PassRole" in str(props.get("pattern_name") or props.get("pattern_id") or "")
    ) else 1
    influence = 0 if rel in _INFLUENCE_BLAST_RELS else 1
    capability = 0 if rel in _CAPABILITY_BLAST_RELS else 1
    reads_last = 1 if rel == "READS" else 0
    return (passrole, influence, reads_last, capability, rel)

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
    exclude_node_ids: set[str] | frozenset[str] | None = None,
) -> list[PathResult]:
    if start_node_id not in graph.nodes:
        return []

    excluded = set(exclude_node_ids or ())
    excluded.discard(start_node_id)
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
            if next_id in excluded and not privesc_outcome:
                continue
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
_INFLUENCE_BLAST_RELS = frozenset(
    {"WRITES", "DELETES", "CONTROLS", "EXECUTES", "FEEDS", "UNLOCKS", "HAS_MATERIAL"}
)
_RESOURCEISH_CONCEPTS = frozenset(
    {
        "DataStore",
        "SecretStore",
        "RegistryStore",
        "RuntimeBinding",
        "Workload",
        "NetworkExposure",
    }
)
# Operational stubs that rarely matter for attack blast (crowd out real impact).
_BLAST_NOISE_NATIVE_PREFIXES = (
    "Logs:",
    "LogGroup:",
    "Ec2Messages:",
    "Ssmmessages:",
    "Tag:",
    "Xray:",
    "Cloudwatch:",
)


def _is_aws_service_linked_role(node_id: str, props: dict) -> bool:
    hay = f"{node_id} {props.get('arn', '')} {props.get('native_id', '')}"
    return "/aws-service-role/" in hay or ":role/aws-service-role/" in hay


def _is_stub_native(native: str) -> bool:
    return "*" in native or native.endswith(":*")


def _is_blast_noise_resource(native: str) -> bool:
    return any(native.startswith(p) or f"/{p}" in native for p in _BLAST_NOISE_NATIVE_PREFIXES)


def _blast_impact_tier(graph: GraphSnapshot, path: PathResult) -> int:
    """Higher = more useful blast story (influence / poison / privesc), not mere READ reachability."""
    node_id = path.target_match.get("node_id") or ""
    node = graph.nodes.get(node_id)
    props = node.props if node else dict(path.target_match or {})
    last = path.steps[-1] if path.steps else None
    last_rel = last.rel_type if last else ""
    last_props = last.evidence if last else {}
    native = str(props.get("native_id") or node_id)
    concept = str(props.get("concept_type") or path.target_match.get("concept_type") or "")
    stub = _is_stub_native(native)
    noise = _is_blast_noise_resource(native)
    hvt = is_high_value(props)
    is_outcome = concept == "AttackOutcome" or bool(path.target_match.get("virtual"))
    passrole = (
        last_rel == "CAN_PRIVESC_TO"
        and "PassRole" in str(last_props.get("pattern_name") or last_props.get("pattern_id") or "")
    )

    if last_rel == "FEEDS":
        return 95
    if last_rel in {"CONTROLS", "WRITES", "DELETES"}:
        if noise:
            return 25
        # CONTROLS on an IAM principal is usually the PassRole resource grant, not the
        # privilege-escalation story — keep it below CAN_PRIVESC_TO / PassRole.
        if concept == "Identity":
            return 52
        # Inventored write/control first; type-wildcard control still = "can create/poison any X".
        return 90 if not stub else 82
    if last_rel == "EXECUTES":
        return 78 if not stub else 72
    if last_rel == "CAN_PRIVESC_TO":
        if passrole or (hvt and not is_outcome):
            return 88
        if is_outcome:
            # Outcomes matter, but must not bury resource influence.
            return 58
        return 55
    if last_rel in {"HAS_MATERIAL", "UNLOCKS", "CAN_ESCAPE_TO", "EXECUTES_AS", "PROJECTS_TO"}:
        return 65
    if last_rel == "READS":
        if noise or stub:
            return 12
        if concept in _RESOURCEISH_CONCEPTS or node_id.startswith("Resource:"):
            return 42
        return 30
    if concept == "Identity":
        return 48 if hvt else 35
    if is_outcome:
        return 50
    return 28


def _blast_label(graph: GraphSnapshot, path: PathResult) -> str:
    """Human label: how we hit the target, not just concept type."""
    node_id = path.target_match.get("node_id") or ""
    node = graph.nodes.get(node_id)
    props = node.props if node else dict(path.target_match or {})
    last = path.steps[-1] if path.steps else None
    last_rel = last.rel_type if last else ""
    if path.target_match.get("outcome_display"):
        name = str(path.target_match["outcome_display"])
    else:
        name = str(
            props.get("display_name")
            or props.get("name")
            or props.get("bucket_name")
            or props.get("native_id")
            or node_id
        )
    if last_rel in _INFLUENCE_BLAST_RELS and _is_stub_native(name):
        return f"{last_rel} {name} (any matching)"
    if last_rel:
        return f"{last_rel} → {name}"
    return name


def _blast_rank_key(graph: GraphSnapshot, path: PathResult) -> tuple:
    """Rank blast hits: exertable influence first, READ stub spam last."""
    node_id = path.target_match.get("node_id") or ""
    node = graph.nodes.get(node_id)
    props = node.props if node else {}
    last = path.steps[-1] if path.steps else None
    last_rel = last.rel_type if last else ""
    last_props = last.evidence if last else {}
    native = str(props.get("native_id") or node_id)
    concept = str(props.get("concept_type") or "")

    tier = _blast_impact_tier(graph, path)
    hvt = 1 if is_high_value(props) else 0
    is_outcome = 1 if concept == "AttackOutcome" or props.get("virtual") else 0

    concrete = 0
    if not _is_stub_native(native) and concept in _RESOURCEISH_CONCEPTS:
        concrete = 2
    elif not _is_stub_native(native) and node_id.startswith("Resource:"):
        concrete = 2

    passrole = 1 if (
        last_rel == "CAN_PRIVESC_TO"
        and "PassRole" in str(last_props.get("pattern_name") or last_props.get("pattern_id") or "")
    ) else 0
    service_noise = 1 if _is_aws_service_linked_role(node_id, props) else 0
    noise_res = 1 if _is_blast_noise_resource(native) else 0
    read_stub = 1 if last_rel == "READS" and _is_stub_native(native) else 0

    return (
        tier,
        concrete,
        hvt,
        passrole,
        -is_outcome,
        -service_noise,
        -noise_res,
        -read_stub,
        path.score,
        -len(path.steps),
    )


def _annotate_blast_path(graph: GraphSnapshot, path: PathResult) -> PathResult:
    path.target_match["impact_tier"] = _blast_impact_tier(graph, path)
    path.target_match["blast_label"] = _blast_label(graph, path)
    return path


def find_forward_reachability(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    rel_types: set[str] | None = None,
    max_depth: int = 6,
    max_paths: int = 20,
    exclude_node_ids: set[str] | frozenset[str] | None = None,
) -> list[PathResult]:
    """Shortest forward path to each reachable node, ranked by exertable influence.

    Completes BFS before truncating. If multiple edges hit the same node, keeps the
    higher-impact hop (WRITES/CONTROLS over READS) so influence isn't lost.
    """
    if start_node_id not in graph.nodes:
        return []

    excluded = set(exclude_node_ids or ())
    excluded.discard(start_node_id)
    allowed_rels = rel_types or TRAVERSABLE_REL_TYPES
    best_by_node: dict[str, PathResult] = {}
    outcome_results: list[PathResult] = []
    queue: deque[tuple[str, int, list[str], list[tuple[str, str, str, dict]]]] = deque()
    queue.append((start_node_id, 0, [start_node_id], []))
    expanded: set[str] = {start_node_id}
    visited_outcomes: set[str] = set()
    max_visit = max(max_paths * 40, 400)

    while queue and len(expanded) <= max_visit:
        current, depth, node_seq, edge_seq = queue.popleft()
        if depth >= max_depth:
            continue

        for next_id, step_src, rel_type, step_dst, props in _iter_traversal_steps(
            graph,
            current,
            direction="out",
            allowed_rels=allowed_rels,
            priority="blast",
        ):
            if is_attack_outcome_edge(rel_type, props) and next_id == current:
                outcome_key = _outcome_path_key(current, props)
                if outcome_key in visited_outcomes:
                    continue
                visited_outcomes.add(outcome_key)
                next_edges = edge_seq + [(step_src, rel_type, step_dst, props)]
                outcome_results.append(
                    _path_result_from_edges(
                        node_seq,
                        next_edges,
                        endpoint_id=current,
                        endpoint_props=virtual_outcome_target(props, current),
                    )
                )
                continue

            if next_id in excluded:
                continue

            next_nodes = node_seq + [next_id]
            next_edges = edge_seq + [(step_src, rel_type, step_dst, props)]
            next_depth = depth + 1
            endpoint = graph.nodes.get(next_id)
            endpoint_props = endpoint.props if endpoint else {}
            candidate = _path_result_from_edges(
                next_nodes,
                next_edges,
                endpoint_id=next_id,
                endpoint_props=endpoint_props,
            )

            existing = best_by_node.get(next_id)
            if existing is not None:
                if _blast_impact_tier(graph, candidate) > _blast_impact_tier(graph, existing):
                    best_by_node[next_id] = candidate
                continue

            best_by_node[next_id] = candidate
            expanded.add(next_id)

            if next_depth < max_depth and len(expanded) < max_visit:
                queue.append((next_id, next_depth, next_nodes, next_edges))

    results = list(best_by_node.values()) + outcome_results
    results.sort(key=lambda p: _blast_rank_key(graph, p), reverse=True)
    return [_annotate_blast_path(graph, p) for p in results[:max_paths]]


def get_blast_radius(
    graph: GraphSnapshot,
    *,
    start_node_id: str,
    max_depth: int = 6,
    max_paths: int = 20,
    rel_types: set[str] | None = None,
    exclude_node_ids: set[str] | frozenset[str] | None = None,
) -> list[PathResult]:
    """Forward reachability ranked by exertable influence (not mere READ stubs)."""
    return find_forward_reachability(
        graph,
        start_node_id=start_node_id,
        rel_types=rel_types,
        max_depth=max_depth,
        max_paths=max_paths,
        exclude_node_ids=exclude_node_ids,
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
    exclude_node_ids: set[str] | frozenset[str] | None = None,
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
        if exclude_node_ids and start_id in exclude_node_ids:
            continue
        targets = end_node_ids or ([end_node_id] if end_node_id else [None])
        for target in targets:
            if target and exclude_node_ids and target in exclude_node_ids:
                continue
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
                exclude_node_ids=exclude_node_ids,
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
    exclude_node_ids: set[str] | frozenset[str] | None = None,
) -> list[PathResult]:
    seen: set[str] = set()
    combined: list[PathResult] = []
    per_start = max(1, max_paths // max(len(start_node_ids), 1))
    for start_id in start_node_ids:
        if exclude_node_ids and start_id in exclude_node_ids:
            continue
        for path in get_blast_radius(
            graph,
            start_node_id=start_id,
            max_depth=max_depth,
            max_paths=per_start,
            rel_types=rel_types,
            exclude_node_ids=exclude_node_ids,
        ):
            if path.path_id in seen:
                continue
            seen.add(path.path_id)
            combined.append(path)
            if len(combined) >= max_paths:
                break
        if len(combined) >= max_paths:
            break
    combined.sort(key=lambda p: _blast_rank_key(graph, p), reverse=True)
    return [_annotate_blast_path(graph, p) for p in combined[:max_paths]]


def find_compromised_to_high_value_paths(
    graph: GraphSnapshot,
    *,
    max_depth: int = 6,
    max_paths: int = 30,
    exclude_node_ids: set[str] | frozenset[str] | None = None,
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
        exclude_node_ids=exclude_node_ids,
    )


def find_paths_to_high_value_nodes(
    graph: GraphSnapshot,
    *,
    start_node_ids: list[str] | None = None,
    max_depth: int = 6,
    max_paths: int = 30,
    exclude_node_ids: set[str] | frozenset[str] | None = None,
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
        exclude_node_ids=exclude_node_ids,
    )
