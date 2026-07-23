"""Neo4j-backed cheap reads (Phase 2): neighbors, search, markings, summary."""

from __future__ import annotations

import json
from typing import Any, Literal

from samoyed.graph.markings import (
    COMPROMISE_MECHANISM,
    MARKING_COMPROMISED,
    MARKING_HIGH_VALUE,
    MARKING_SHADOW_ADMIN,
)
from samoyed.graph.neo4j_store import _deserialize_props, get_driver, neo4j_configured


def session_exists(session_id: str) -> bool:
    driver = get_driver()
    if driver is None:
        return False
    with driver.session() as session:
        row = session.run(
            "MATCH (s:CollectionSession {session_id: $sid}) RETURN s.session_id AS sid LIMIT 1",
            sid=session_id,
        ).single()
    return bool(row)


def _node_props(raw: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    props = _deserialize_props(dict(raw))
    node_id = str(props.pop("node_id", "") or "")
    label = str(props.pop("label", "Unknown") or "Unknown")
    for key in ("session_id", "samoyed_key"):
        props.pop(key, None)
    return node_id, label, props


def _display(props: dict[str, Any], node_id: str) -> str:
    return str(
        props.get("display_name")
        or props.get("native_id")
        or props.get("arn")
        or node_id
    )


def search_nodes(
    session_id: str,
    *,
    q: str = "",
    concept_type: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]] | None:
    """Search session nodes in Neo4j. Returns None if Neo4j is unavailable / session missing."""
    if not neo4j_configured() or not session_exists(session_id):
        return None
    driver = get_driver()
    assert driver is not None
    q_lower = (q or "").lower()
    with driver.session() as session:
        rows = session.run(
            """
            MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(n:SamoyedNode)
            WHERE ($concept IS NULL OR n.concept_type = $concept)
            RETURN n
            LIMIT $fetch
            """,
            sid=session_id,
            concept=concept_type,
            fetch=max(limit * 20, 200),
        )
        results: list[dict[str, Any]] = []
        for row in rows:
            node_id, label, props = _node_props(dict(row["n"]))
            if not node_id or label == "CollectionSession":
                continue
            haystack = " ".join(
                str(props.get(k, ""))
                for k in ("native_id", "display_name", "arn", "name", "namespace", "concept_type")
            ).lower()
            haystack += f" {node_id.lower()} {label.lower()}"
            if q_lower and q_lower not in haystack:
                continue
            results.append(
                {
                    "id": node_id,
                    "label": label,
                    "display": _display(props, node_id),
                    **props,
                }
            )
            if len(results) >= limit:
                break
    return results


def get_neighbors(
    session_id: str,
    node_id: str,
    *,
    rel_type: str | None = None,
    direction: Literal["out", "in", "both"] = "out",
) -> list[dict[str, Any]] | None:
    if not neo4j_configured() or not session_exists(session_id):
        return None
    driver = get_driver()
    assert driver is not None
    neighbors: list[dict[str, Any]] = []
    with driver.session() as session:
        if direction in {"out", "both"}:
            rows = session.run(
                """
                MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(a:SamoyedNode {node_id: $nid})
                      -[r]->(b:SamoyedNode)
                WHERE b.session_id = $sid
                  AND type(r) <> 'DISCOVERED'
                  AND ($rel IS NULL OR type(r) = $rel)
                RETURN type(r) AS rel, properties(r) AS edge_props, b AS node
                """,
                sid=session_id,
                nid=node_id,
                rel=rel_type,
            )
            for row in rows:
                dst_id, label, props = _node_props(dict(row["node"]))
                neighbors.append(
                    {
                        "direction": "out",
                        "rel_type": row["rel"],
                        "node_id": dst_id,
                        "label": label,
                        "props": props,
                        "edge_props": dict(row["edge_props"] or {}),
                    }
                )
        if direction in {"in", "both"}:
            rows = session.run(
                """
                MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(b:SamoyedNode {node_id: $nid})
                      <-[r]-(a:SamoyedNode)
                WHERE a.session_id = $sid
                  AND type(r) <> 'DISCOVERED'
                  AND ($rel IS NULL OR type(r) = $rel)
                RETURN type(r) AS rel, properties(r) AS edge_props, a AS node
                """,
                sid=session_id,
                nid=node_id,
                rel=rel_type,
            )
            for row in rows:
                src_id, label, props = _node_props(dict(row["node"]))
                neighbors.append(
                    {
                        "direction": "in",
                        "rel_type": row["rel"],
                        "node_id": src_id,
                        "label": label,
                        "props": props,
                        "edge_props": dict(row["edge_props"] or {}),
                    }
                )
    return neighbors


def list_markings(session_id: str) -> dict[str, Any] | None:
    if not neo4j_configured() or not session_exists(session_id):
        return None
    driver = get_driver()
    assert driver is not None
    compromised: list[dict[str, Any]] = []
    high_value: list[dict[str, Any]] = []
    shadow_admins: list[dict[str, Any]] = []
    shared_envs: list[dict[str, Any]] = []
    with driver.session() as session:
        rows = session.run(
            """
            MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(n:SamoyedNode)
            WHERE n.is_compromised = true
               OR n.is_caller = true
               OR n.is_scenario_start = true
               OR n.is_high_value = true
               OR n.is_shadow_admin = true
               OR n.shared_across_envs = true
            RETURN n
            """,
            sid=session_id,
        )
        for row in rows:
            node_id, _label, props = _node_props(dict(row["n"]))
            entry = {
                "node_id": node_id,
                "display": _display(props, node_id),
                "concept_type": props.get("concept_type"),
                "marking_source": props.get("marking_source"),
                "mechanism": props.get(COMPROMISE_MECHANISM),
            }
            if props.get(MARKING_COMPROMISED) or props.get("is_caller") or props.get("is_scenario_start"):
                compromised.append(entry)
            if props.get(MARKING_HIGH_VALUE):
                high_value.append(entry)
            if props.get(MARKING_SHADOW_ADMIN):
                shadow_admins.append(
                    {
                        **entry,
                        "reason": props.get("shadow_admin_reason"),
                        "mechanism": props.get("shadow_admin_mechanism")
                        or props.get(COMPROMISE_MECHANISM),
                    }
                )
            if props.get("shared_across_envs"):
                envs = props.get("shared_environments") or []
                if isinstance(envs, str):
                    try:
                        envs = json.loads(envs)
                    except json.JSONDecodeError:
                        envs = [envs]
                shared_envs.append(
                    {
                        **entry,
                        "environments": envs,
                        "reason": props.get("shared_env_reason"),
                    }
                )
    return {
        "compromised_count": len(compromised),
        "high_value_count": len(high_value),
        "shadow_admin_count": len(shadow_admins),
        "shared_across_envs_count": len(shared_envs),
        "compromised": compromised,
        "high_value": high_value,
        "shadow_admins": shadow_admins,
        "shared_across_envs": shared_envs,
    }


def graph_summary(session_id: str) -> dict[str, Any] | None:
    """Node/edge counts + concept histogram without hydrating the full graph."""
    if not neo4j_configured() or not session_exists(session_id):
        return None
    driver = get_driver()
    assert driver is not None
    with driver.session() as session:
        node_rows = session.run(
            """
            MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(n:SamoyedNode)
            RETURN coalesce(n.concept_type, n.label) AS concept, count(*) AS cnt
            """,
            sid=session_id,
        )
        concepts: dict[str, int] = {}
        node_count = 0
        for row in node_rows:
            concept = str(row["concept"] or "Unknown")
            cnt = int(row["cnt"])
            concepts[concept] = cnt
            node_count += cnt
        edge_row = session.run(
            """
            MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(a:SamoyedNode)
                  -[r]->(b:SamoyedNode)<-[:DISCOVERED]-(s)
            WHERE type(r) <> 'DISCOVERED'
            RETURN count(r) AS edge_count
            """,
            sid=session_id,
        ).single()
        edge_count = int(edge_row["edge_count"]) if edge_row else 0
    return {
        "node_count": node_count,
        "edge_count": edge_count,
        "concepts": concepts,
    }


def get_node(session_id: str, node_id: str) -> dict[str, Any] | None:
    """Fetch one node. Returns None if missing / Neo4j unavailable."""
    if not neo4j_configured() or not session_exists(session_id):
        return None
    driver = get_driver()
    assert driver is not None
    with driver.session() as session:
        row = session.run(
            """
            MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(n:SamoyedNode {node_id: $nid})
            RETURN n
            """,
            sid=session_id,
            nid=node_id,
        ).single()
    if not row:
        return None
    nid, label, props = _node_props(dict(row["n"]))
    return {"id": nid, "label": label, **props}
