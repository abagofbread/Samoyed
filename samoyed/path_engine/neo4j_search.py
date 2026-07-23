"""Cypher-backed path and blast search (Phase 3).

Walks live in Neo4j; scoring / blast ranking reuse the in-memory helpers so
results stay comparable to the Python BFS engine.
"""

from __future__ import annotations

from typing import Any, Literal

from samoyed.cloud.concepts import TRAVERSABLE_REL_TYPES
from samoyed.graph.markings import is_high_value
from samoyed.graph.model import GraphNode, GraphSnapshot
from samoyed.graph.neo4j_query import session_exists
from samoyed.graph.neo4j_store import _safe_rel, get_driver, neo4j_configured
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import (
    _annotate_blast_path,
    _blast_rank_key,
    _path_result_from_edges,
)

Direction = Literal["out", "in", "both"]


def _rel_union(rel_types: set[str] | frozenset[str]) -> str:
    parts = sorted(_safe_rel(r) for r in rel_types)
    if not parts:
        raise ValueError("No traversable relationship types")
    return "|".join(parts)


def _strip_managed(props: dict[str, Any]) -> dict[str, Any]:
    out = dict(props)
    for key in ("node_id", "label", "session_id", "samoyed_key"):
        out.pop(key, None)
    return out


def _matches_target_props(
    node_id: str,
    props: dict[str, Any],
    *,
    target_concept: str | None,
    target_resource_type: str | None,
    end_node_id: str | None,
    end_id_contains: str | None,
) -> bool:
    if end_node_id and node_id == end_node_id:
        return True
    if end_id_contains:
        haystack = (
            " ".join(
                str(props.get(key) or "")
                for key in ("native_id", "arn", "display_name", "name", "bucket_name")
            )
            + " "
            + node_id
        )
        if end_id_contains.lower() in haystack.lower():
            return True
    if target_concept in {"high_value", "HighValue", "crown_jewel", "crown-jewel"}:
        return is_high_value(props)
    if target_concept and props.get("concept_type") == target_concept:
        return True
    if target_resource_type and props.get("resource_type") == target_resource_type:
        return True
    if not target_concept and not target_resource_type and not end_node_id and not end_id_contains:
        return False
    return False


def _rows_to_paths(
    rows: list[dict[str, Any]],
    *,
    max_paths: int,
    require_target: bool,
    target_concept: str | None = None,
    target_resource_type: str | None = None,
    end_node_id: str | None = None,
    end_id_contains: str | None = None,
) -> list[PathResult]:
    results: list[PathResult] = []
    seen: set[str] = set()
    for row in rows:
        node_ids = list(row["node_ids"] or [])
        rels = list(row["rels"] or [])
        edge_props = [dict(p or {}) for p in (row["edge_props"] or [])]
        edge_srcs = list(row.get("edge_srcs") or [])
        edge_dsts = list(row.get("edge_dsts") or [])
        end_props = _strip_managed(dict(row["end_props"] or {}))
        if len(node_ids) < 2 or len(rels) != len(node_ids) - 1:
            continue
        end_id = node_ids[-1]
        if require_target and not _matches_target_props(
            end_id,
            end_props,
            target_concept=target_concept,
            target_resource_type=target_resource_type,
            end_node_id=end_node_id,
            end_id_contains=end_id_contains,
        ):
            continue
        edge_seq = []
        for i, rel in enumerate(rels):
            src = edge_srcs[i] if i < len(edge_srcs) and edge_srcs[i] else node_ids[i]
            dst = edge_dsts[i] if i < len(edge_dsts) and edge_dsts[i] else node_ids[i + 1]
            edge_seq.append((src, rel, dst, edge_props[i] if i < len(edge_props) else {}))
        path = _path_result_from_edges(
            node_ids,
            edge_seq,
            endpoint_id=end_id,
            endpoint_props=end_props,
        )
        if path.path_id in seen:
            continue
        seen.add(path.path_id)
        results.append(path)
        if len(results) >= max_paths * 3:
            break
    results.sort(key=lambda p: p.score, reverse=True)
    return results[:max_paths]


def find_attack_paths(
    session_id: str,
    *,
    start_node_id: str,
    target_concept: str | None = None,
    target_resource_type: str | None = None,
    end_node_id: str | None = None,
    end_id_contains: str | None = None,
    end_node_ids: list[str] | None = None,
    rel_types: set[str] | None = None,
    direction: Direction = "both",
    max_depth: int = 6,
    max_paths: int = 10,
    exclude_node_ids: set[str] | frozenset[str] | None = None,
) -> list[PathResult] | None:
    """Cypher path search. Returns None if Neo4j/session unavailable."""
    if not neo4j_configured() or not session_exists(session_id):
        return None
    driver = get_driver()
    assert driver is not None

    allowed = set(rel_types or TRAVERSABLE_REL_TYPES)
    rel_pat = _rel_union(allowed)
    excluded = list((exclude_node_ids or set()) - {start_node_id})
    depth = max(1, min(int(max_depth), 12))

    end_filter = ["end.session_id = $sid", "end.node_id <> start.node_id"]
    if end_node_id:
        end_filter.append("end.node_id = $end_node_id")
    if end_node_ids:
        end_filter.append("end.node_id IN $end_node_ids")
    if target_concept in {"high_value", "HighValue", "crown_jewel", "crown-jewel"}:
        end_filter.append("end.is_high_value = true")
    elif target_concept:
        end_filter.append("end.concept_type = $target_concept")
    if target_resource_type:
        end_filter.append("end.resource_type = $target_resource_type")

    # Undirected shortestPath over many rel types is pathological on real graphs.
    directions: list[Direction] = ["out", "in"] if direction == "both" else [direction]
    params = {
        "sid": session_id,
        "start": start_node_id,
        "excluded": excluded,
        "end_node_id": end_node_id,
        "end_node_ids": list(end_node_ids or []),
        "target_concept": target_concept,
        "target_resource_type": target_resource_type,
        "fetch": max(max_paths * 5, 50),
    }
    rows: list[dict[str, Any]] = []
    with driver.session() as session:
        for direc in directions:
            arrow = (
                f"(start)-[:{rel_pat}*1..{depth}]->(end)"
                if direc == "out"
                else f"(start)<-[:{rel_pat}*1..{depth}]-(end)"
            )
            cypher = f"""
            MATCH (s:CollectionSession {{session_id: $sid}})-[:DISCOVERED]->(start:SamoyedNode {{node_id: $start}})
            MATCH (s)-[:DISCOVERED]->(end:SamoyedNode)
            WHERE {" AND ".join(end_filter)}
            MATCH path = shortestPath({arrow})
            WHERE ALL(n IN nodes(path) WHERE n:SamoyedNode AND n.session_id = $sid)
              AND NONE(n IN nodes(path)[1..] WHERE n.node_id IN $excluded)
            RETURN [n IN nodes(path) | n.node_id] AS node_ids,
                   [r IN relationships(path) | type(r)] AS rels,
                   [r IN relationships(path) | properties(r)] AS edge_props,
                   [r IN relationships(path) | startNode(r).node_id] AS edge_srcs,
                   [r IN relationships(path) | endNode(r).node_id] AS edge_dsts,
                   properties(end) AS end_props
            LIMIT $fetch
            """
            rows.extend(dict(r) for r in session.run(cypher, **params))

    require_target = bool(
        target_concept or target_resource_type or end_node_id or end_id_contains or end_node_ids
    )
    return _rows_to_paths(
        rows,
        max_paths=max_paths,
        require_target=require_target or bool(end_id_contains),
        target_concept=target_concept,
        target_resource_type=target_resource_type,
        end_node_id=end_node_id,
        end_id_contains=end_id_contains,
    )


def get_blast_radius(
    session_id: str,
    *,
    start_node_id: str,
    max_depth: int = 6,
    max_paths: int = 20,
    rel_types: set[str] | None = None,
    exclude_node_ids: set[str] | frozenset[str] | None = None,
) -> list[PathResult] | None:
    """Forward Cypher reachability, ranked with the shared blast scorer."""
    if not neo4j_configured() or not session_exists(session_id):
        return None
    driver = get_driver()
    assert driver is not None

    allowed = set(rel_types or TRAVERSABLE_REL_TYPES)
    rel_pat = _rel_union(allowed)
    excluded = list((exclude_node_ids or set()) - {start_node_id})
    depth = max(1, min(int(max_depth), 12))
    fetch = max(max_paths * 60, 200)

    cypher = f"""
    MATCH (s:CollectionSession {{session_id: $sid}})-[:DISCOVERED]->(start:SamoyedNode {{node_id: $start}})
    MATCH path = (start)-[rs:{rel_pat}*1..{depth}]->(end:SamoyedNode)
    WHERE end.session_id = $sid
      AND ALL(n IN nodes(path) WHERE n:SamoyedNode AND n.session_id = $sid)
      AND NONE(n IN nodes(path)[1..] WHERE n.node_id IN $excluded)
      AND end.node_id <> start.node_id
    WITH end, path, length(path) AS hops
    ORDER BY hops ASC
    WITH end, collect(path)[0] AS path
    RETURN [n IN nodes(path) | n.node_id] AS node_ids,
           [r IN relationships(path) | type(r)] AS rels,
           [r IN relationships(path) | properties(r)] AS edge_props,
           [r IN relationships(path) | startNode(r).node_id] AS edge_srcs,
           [r IN relationships(path) | endNode(r).node_id] AS edge_dsts,
           properties(end) AS end_props,
           end.label AS end_label
    LIMIT $fetch
    """
    with driver.session() as session:
        rows = [dict(r) for r in session.run(
            cypher,
            sid=session_id,
            start=start_node_id,
            excluded=excluded,
            fetch=fetch,
        )]

    mini = GraphSnapshot(session_id=session_id)
    paths: list[PathResult] = []
    seen: set[str] = set()
    for row in rows:
        node_ids = list(row["node_ids"] or [])
        rels = list(row["rels"] or [])
        edge_props = [dict(p or {}) for p in (row["edge_props"] or [])]
        edge_srcs = list(row.get("edge_srcs") or [])
        edge_dsts = list(row.get("edge_dsts") or [])
        end_props = _strip_managed(dict(row["end_props"] or {}))
        if len(node_ids) < 2 or len(rels) != len(node_ids) - 1:
            continue
        end_id = node_ids[-1]
        label = str(row.get("end_label") or end_props.get("label") or "Unknown")
        if end_id not in mini.nodes:
            mini.add_node(GraphNode(node_id=end_id, label=label, props=end_props))
        edge_seq = []
        for i, rel in enumerate(rels):
            src = edge_srcs[i] if i < len(edge_srcs) and edge_srcs[i] else node_ids[i]
            dst = edge_dsts[i] if i < len(edge_dsts) and edge_dsts[i] else node_ids[i + 1]
            edge_seq.append((src, rel, dst, edge_props[i] if i < len(edge_props) else {}))
        path = _path_result_from_edges(
            node_ids,
            edge_seq,
            endpoint_id=end_id,
            endpoint_props=end_props,
        )
        if path.path_id in seen:
            continue
        seen.add(path.path_id)
        paths.append(path)

    paths.sort(key=lambda p: _blast_rank_key(mini, p), reverse=True)
    return [_annotate_blast_path(mini, p) for p in paths[:max_paths]]


def find_high_value_node_ids(session_id: str) -> list[str] | None:
    if not neo4j_configured() or not session_exists(session_id):
        return None
    driver = get_driver()
    assert driver is not None
    with driver.session() as session:
        rows = session.run(
            """
            MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(n:SamoyedNode)
            WHERE n.is_high_value = true
            RETURN n.node_id AS node_id
            """,
            sid=session_id,
        )
        return [r["node_id"] for r in rows if r["node_id"]]
