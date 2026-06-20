from __future__ import annotations

import json
import os
from typing import Any

from samoyed.graph.model import GraphSnapshot


def neo4j_configured() -> bool:
    return bool(os.environ.get("NEO4J_URI"))


def write_snapshot(snapshot: GraphSnapshot, *, session_meta: dict[str, Any] | None = None) -> None:
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        return
    from neo4j import GraphDatabase

    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "samoyed-dev")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    meta = {"session_id": snapshot.session_id, **(session_meta or {})}
    with driver.session() as session:
        session.run(
            "CREATE CONSTRAINT session_id IF NOT EXISTS FOR (s:CollectionSession) REQUIRE s.session_id IS UNIQUE"
        )
        session.run(
            "MERGE (s:CollectionSession {session_id: $sid}) SET s += $meta, s.updated = timestamp()",
            sid=snapshot.session_id,
            meta=meta,
        )
        for node in snapshot.nodes.values():
            session.run(
                f"MERGE (n:{node.label} {{node_id: $node_id}}) SET n += $props "
                "WITH n MATCH (s:CollectionSession {session_id: $sid}) MERGE (s)-[:DISCOVERED]->(n)",
                node_id=node.node_id,
                props={**node.props, "node_id": node.node_id, "label": node.label},
                sid=snapshot.session_id,
            )
        for edge in snapshot.edges:
            session.run(
                "MATCH (a {node_id: $src}), (b {node_id: $dst}) "
                f"MERGE (a)-[r:{edge.rel_type}]->(b) SET r += $props",
                src=edge.src_id,
                dst=edge.dst_id,
                props=edge.props,
            )
    driver.close()


def load_snapshot(session_id: str) -> GraphSnapshot | None:
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        return None
    from neo4j import GraphDatabase

    from samoyed.graph.model import GraphEdge, GraphNode

    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "samoyed-dev")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    snapshot = GraphSnapshot(session_id=session_id)
    with driver.session() as session:
        rows = session.run(
            "MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(n) RETURN n",
            sid=session_id,
        )
        for row in rows:
            n = row["n"]
            props = dict(n)
            node_id = props.pop("node_id")
            label = props.pop("label", "Unknown")
            snapshot.add_node(GraphNode(node_id=node_id, label=label, props=props))
        erows = session.run(
            "MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(a)-[r]->(b) "
            "<-[:DISCOVERED]-(s) RETURN a.node_id AS src, type(r) AS rel, b.node_id AS dst, properties(r) AS props",
            sid=session_id,
        )
        for row in erows:
            props = dict(row["props"] or {})
            snapshot.add_edge(
                GraphEdge(src_id=row["src"], rel_type=row["rel"], dst_id=row["dst"], props=props)
            )
    driver.close()
    if not snapshot.nodes:
        return None
    return snapshot


def load_session_meta(session_id: str) -> dict[str, Any] | None:
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        return None
    from neo4j import GraphDatabase

    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "samoyed-dev")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        row = session.run(
            "MATCH (s:CollectionSession {session_id: $sid}) RETURN properties(s) AS props",
            sid=session_id,
        ).single()
    driver.close()
    if not row:
        return None
    props = dict(row["props"])
    props.pop("updated", None)
    return props


def list_session_summaries() -> list[dict[str, Any]]:
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        return []
    from neo4j import GraphDatabase

    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "samoyed-dev")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        rows = session.run(
            "MATCH (s:CollectionSession) "
            "OPTIONAL MATCH (s)-[:DISCOVERED]->(n) "
            "RETURN s.session_id AS session_id, properties(s) AS props, count(n) AS node_count "
            "ORDER BY s.created_at DESC"
        )
        out = []
        for row in rows:
            props = dict(row["props"] or {})
            denial_log = props.pop("denial_log_json", None)
            metadata = props.pop("metadata_json", None)
            if isinstance(metadata, str):
                metadata = json.loads(metadata)
            out.append(
                {
                    "session_id": row["session_id"],
                    "caller_arn": props.get("caller_arn", "unknown"),
                    "created_at": props.get("created_at", ""),
                    "provider": props.get("provider", "aws"),
                    "scope_id": props.get("scope_id", ""),
                    "status": props.get("status", "complete"),
                    "metadata": metadata or {"node_count": row["node_count"]},
                    "denial_log_json": denial_log,
                }
            )
    driver.close()
    return out


_WRITE_KEYWORDS = frozenset(
    {
        "CREATE",
        "MERGE",
        "SET",
        "DELETE",
        "DETACH",
        "REMOVE",
        "DROP",
        "CALL",
        "LOAD",
        "FOREACH",
    }
)


def run_readonly_cypher(query: str, *, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        raise RuntimeError("NEO4J_URI is not configured")
    normalized = query.strip().upper()
    for keyword in _WRITE_KEYWORDS:
        if keyword in normalized:
            raise ValueError(f"Write operations are not allowed in read-only Cypher ({keyword})")

    from neo4j import GraphDatabase

    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "samoyed-dev")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    rows_out: list[dict[str, Any]] = []
    with driver.session() as session:
        result = session.run(query, **(params or {}))
        for record in result:
            row: dict[str, Any] = {}
            for key in record.keys():
                value = record[key]
                if hasattr(value, "items"):
                    row[key] = dict(value)
                elif hasattr(value, "__iter__") and not isinstance(value, (str, bytes)):
                    row[key] = list(value)
                else:
                    row[key] = value
            rows_out.append(row)
    driver.close()
    return rows_out
