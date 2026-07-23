"""Neo4j persistence for Samoyed session graphs.

When ``NEO4J_URI`` is set, Neo4j is the durable source of truth for session
graphs. Nodes are session-scoped (``node_id`` + ``session_id``) so replace
writes and deletes never leak edges across sessions. JSON under
``~/.samoyed/sessions`` remains a local cache/export.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import threading
from typing import Any

from samoyed.graph.model import GraphEdge, GraphNode, GraphSnapshot

_DRIVER = None
_DRIVER_LOCK = threading.Lock()
_CONSTRAINTS_READY = False

_LABEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Reserved props we manage; stripped on load so GraphSnapshot stays clean.
_MANAGED_NODE_PROPS = frozenset({"node_id", "label", "session_id", "samoyed_key"})


def neo4j_configured() -> bool:
    return bool(os.environ.get("NEO4J_URI"))


def _auth() -> tuple[str, str]:
    return (
        os.environ.get("NEO4J_USER", "neo4j"),
        os.environ.get("NEO4J_PASSWORD", "samoyed-dev"),
    )


def get_driver():
    """Return a process-wide Neo4j driver, or None if ``NEO4J_URI`` is unset."""
    global _DRIVER
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        return None
    with _DRIVER_LOCK:
        if _DRIVER is None:
            from neo4j import GraphDatabase

            user, password = _auth()
            _DRIVER = GraphDatabase.driver(uri, auth=(user, password))
        return _DRIVER


def close_driver() -> None:
    """Close the shared driver (tests / shutdown)."""
    global _DRIVER, _CONSTRAINTS_READY
    with _DRIVER_LOCK:
        if _DRIVER is not None:
            _DRIVER.close()
            _DRIVER = None
        _CONSTRAINTS_READY = False


atexit.register(close_driver)


def _safe_label(label: str) -> str:
    text = (label or "Unknown").strip()
    if not _LABEL_RE.match(text):
        raise ValueError(f"Invalid Neo4j node label: {label!r}")
    return text


def _safe_rel(rel_type: str) -> str:
    text = (rel_type or "RELATED").strip()
    if not _REL_RE.match(text):
        raise ValueError(f"Invalid Neo4j relationship type: {rel_type!r}")
    return text


def _samoyed_key(session_id: str, node_id: str) -> str:
    return f"{session_id}|{node_id}"


def _ensure_constraints(session) -> None:
    global _CONSTRAINTS_READY
    if _CONSTRAINTS_READY:
        return
    session.run(
        "CREATE CONSTRAINT samoyed_session_id IF NOT EXISTS "
        "FOR (s:CollectionSession) REQUIRE s.session_id IS UNIQUE"
    )
    session.run(
        "CREATE CONSTRAINT samoyed_node_key IF NOT EXISTS "
        "FOR (n:SamoyedNode) REQUIRE n.samoyed_key IS UNIQUE"
    )
    _CONSTRAINTS_READY = True


def _serialize_props(props: dict[str, Any] | None) -> dict[str, Any]:
    """Neo4j only accepts primitives / arrays of primitives."""
    out: dict[str, Any] = {}
    for key, value in (props or {}).items():
        if value is None:
            continue
        if isinstance(value, (bool, int, float, str)):
            out[key] = value
        elif isinstance(value, (list, tuple)):
            if all(isinstance(item, (bool, int, float, str)) or item is None for item in value):
                out[key] = [item for item in value if item is not None]
            else:
                out[key] = json.dumps(value)
        elif isinstance(value, dict):
            out[key] = json.dumps(value)
        else:
            out[key] = str(value)
    return out


def _deserialize_props(props: dict[str, Any] | None) -> dict[str, Any]:
    """Inverse of ``_serialize_props`` — restore JSON-encoded dict/list values."""
    out: dict[str, Any] = {}
    for key, value in (props or {}).items():
        if isinstance(value, str) and value[:1] in {"{", "["}:
            try:
                out[key] = json.loads(value)
                continue
            except (json.JSONDecodeError, TypeError):
                pass
        out[key] = value
    return out


def _purge_session_graph(session, session_id: str) -> None:
    """Detach-delete all nodes owned by a session, then the session root."""
    session.run(
        """
        MATCH (s:CollectionSession {session_id: $sid})
        OPTIONAL MATCH (s)-[:DISCOVERED]->(n:SamoyedNode)
        WITH s, collect(DISTINCT n) AS nodes
        FOREACH (n IN nodes | DETACH DELETE n)
        DETACH DELETE s
        """,
        sid=session_id,
    )


def write_snapshot(snapshot: GraphSnapshot, *, session_meta: dict[str, Any] | None = None) -> None:
    """Replace the session subgraph in Neo4j (no-op if ``NEO4J_URI`` unset)."""
    driver = get_driver()
    if driver is None:
        return

    meta = _serialize_props({"session_id": snapshot.session_id, **(session_meta or {})})
    sid = snapshot.session_id

    nodes_by_label: dict[str, list[dict[str, Any]]] = {}
    for node in snapshot.nodes.values():
        # Session root is written separately; embedding another CollectionSession
        # node with the same session_id trips the uniqueness constraint.
        if node.label == "CollectionSession":
            continue
        label = _safe_label(node.label)
        props = _serialize_props(node.props)
        props.update(
            {
                "node_id": node.node_id,
                "label": label,
                "session_id": sid,
                "samoyed_key": _samoyed_key(sid, node.node_id),
            }
        )
        nodes_by_label.setdefault(label, []).append(props)

    edges_by_rel: dict[str, list[dict[str, Any]]] = {}
    for edge in snapshot.edges:
        # DISCOVERED links to the session root are recreated below; skip
        # in-graph CollectionSession endpoints we did not write.
        if edge.rel_type == "DISCOVERED" and (
            edge.src_id.startswith("CollectionSession:")
            or edge.dst_id.startswith("CollectionSession:")
        ):
            continue
        if edge.src_id.startswith("CollectionSession:") or edge.dst_id.startswith(
            "CollectionSession:"
        ):
            continue
        rel = _safe_rel(edge.rel_type)
        edges_by_rel.setdefault(rel, []).append(
            {
                "src": edge.src_id,
                "dst": edge.dst_id,
                "props": _serialize_props(edge.props),
            }
        )

    with driver.session() as session:
        _ensure_constraints(session)
        _purge_session_graph(session, sid)
        session.run(
            "CREATE (s:CollectionSession) SET s += $meta, s.updated = timestamp()",
            meta=meta,
        )
        for label, rows in nodes_by_label.items():
            session.run(
                f"""
                UNWIND $rows AS row
                CREATE (n:SamoyedNode:{label})
                SET n = row
                WITH n
                MATCH (s:CollectionSession {{session_id: $sid}})
                CREATE (s)-[:DISCOVERED]->(n)
                """,
                rows=rows,
                sid=sid,
            )
        for rel, rows in edges_by_rel.items():
            session.run(
                f"""
                UNWIND $rows AS row
                MATCH (a:SamoyedNode {{session_id: $sid, node_id: row.src}})
                MATCH (b:SamoyedNode {{session_id: $sid, node_id: row.dst}})
                CREATE (a)-[r:{rel}]->(b)
                SET r = row.props
                """,
                rows=rows,
                sid=sid,
            )


def load_snapshot(session_id: str) -> GraphSnapshot | None:
    driver = get_driver()
    if driver is None:
        return None

    snapshot = GraphSnapshot(session_id=session_id)
    with driver.session() as session:
        rows = session.run(
            "MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(n:SamoyedNode) "
            "RETURN n",
            sid=session_id,
        )
        for row in rows:
            n = row["n"]
            props = _deserialize_props(dict(n))
            node_id = props.pop("node_id", None)
            if not node_id:
                continue
            label = props.pop("label", None) or next(
                (lbl for lbl in n.labels if lbl != "SamoyedNode"), "Unknown"
            )
            for key in _MANAGED_NODE_PROPS:
                props.pop(key, None)
            snapshot.add_node(GraphNode(node_id=node_id, label=label, props=props))

        erows = session.run(
            """
            MATCH (s:CollectionSession {session_id: $sid})-[:DISCOVERED]->(a:SamoyedNode)
                  -[r]->(b:SamoyedNode)<-[:DISCOVERED]-(s)
            WHERE type(r) <> 'DISCOVERED'
            RETURN a.node_id AS src, type(r) AS rel, b.node_id AS dst, properties(r) AS props
            """,
            sid=session_id,
        )
        for row in erows:
            props = _deserialize_props(dict(row["props"] or {}))
            snapshot.add_edge(
                GraphEdge(src_id=row["src"], rel_type=row["rel"], dst_id=row["dst"], props=props)
            )

    if not snapshot.nodes:
        return None
    return snapshot


def load_session_meta(session_id: str) -> dict[str, Any] | None:
    driver = get_driver()
    if driver is None:
        return None
    with driver.session() as session:
        row = session.run(
            "MATCH (s:CollectionSession {session_id: $sid}) RETURN properties(s) AS props",
            sid=session_id,
        ).single()
    if not row:
        return None
    props = dict(row["props"])
    props.pop("updated", None)
    return props


def list_session_summaries() -> list[dict[str, Any]]:
    driver = get_driver()
    if driver is None:
        return []
    with driver.session() as session:
        rows = session.run(
            """
            MATCH (s:CollectionSession)
            OPTIONAL MATCH (s)-[:DISCOVERED]->(n:SamoyedNode)
            RETURN s.session_id AS session_id, properties(s) AS props, count(n) AS node_count
            ORDER BY coalesce(s.created_at, '') DESC
            """
        )
        out = []
        for row in rows:
            props = dict(row["props"] or {})
            denial_log = props.pop("denial_log_json", None)
            metadata = props.pop("metadata_json", None)
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    metadata = {}
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
    return out


def delete_snapshot(session_id: str) -> bool:
    """Remove a session and all nodes it discovered (session-scoped ownership)."""
    driver = get_driver()
    if driver is None:
        return False
    with driver.session() as session:
        _ensure_constraints(session)
        result = session.run(
            """
            MATCH (s:CollectionSession {session_id: $sid})
            OPTIONAL MATCH (s)-[:DISCOVERED]->(n:SamoyedNode)
            WITH s, collect(DISTINCT n) AS nodes, count(s) AS found
            FOREACH (n IN nodes | DETACH DELETE n)
            DETACH DELETE s
            RETURN found
            """,
            sid=session_id,
        ).single()
    return bool(result and result["found"])


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
    driver = get_driver()
    if driver is None:
        raise RuntimeError("NEO4J_URI is not configured")
    normalized = query.strip().upper()
    for keyword in _WRITE_KEYWORDS:
        if keyword in normalized:
            raise ValueError(f"Write operations are not allowed in read-only Cypher ({keyword})")

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
    return rows_out
