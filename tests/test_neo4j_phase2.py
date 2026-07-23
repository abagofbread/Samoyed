"""Phase 2: Neo4j-backed neighbors / search / markings / summary."""

from __future__ import annotations

import os

import pytest

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import apply_marking
from samoyed.graph.neo4j_store import close_driver, delete_snapshot, write_snapshot
from samoyed.graph import neo4j_query as neo4j_reads
from samoyed.sessions import SessionRecord, SessionStore
from samoyed.cloud.artifacts import DenialLog
from samoyed.cloud.concepts import CloudProvider
from datetime import datetime, timezone


def _neo4j_ready() -> bool:
    if not os.environ.get("NEO4J_URI"):
        return False
    try:
        from samoyed.graph.neo4j_store import get_driver

        driver = get_driver()
        if driver is None:
            return False
        driver.verify_connectivity()
        return True
    except Exception:
        close_driver()
        return False


@pytest.fixture
def neo4j_session(monkeypatch):
    if not os.environ.get("NEO4J_URI"):
        monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7688")
        monkeypatch.setenv("NEO4J_USER", "neo4j")
        monkeypatch.setenv("NEO4J_PASSWORD", "samoyed-dev")
    close_driver()
    if not _neo4j_ready():
        pytest.skip("Neo4j not available")
    yield
    close_driver()


def _seed(session_id: str = "test-neo4j-phase2") -> GraphBuilder:
    builder = GraphBuilder(session_id)
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/alice",
        props={"native_kind": "User", "display_name": "alice", "is_caller": True},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="arn:aws:secretsmanager:us-east-1:1:secret:demo",
        props={"native_kind": "Secret", "name": "demo", "display_name": "demo-secret"},
    )
    apply_marking(builder.snapshot.nodes[secret].props, high_value=True, source="test")
    builder.add_edge(src_id=user, rel_type="READS", dst_id=secret, props={"action": "GetSecretValue"})
    builder.link_session(user)
    builder.link_session(secret)
    write_snapshot(
        builder.snapshot,
        session_meta={
            "session_id": session_id,
            "caller_arn": "arn:aws:iam::1:user/alice",
            "provider": "aws",
            "scope_id": "aws:1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "status": "complete",
            "metadata_json": "{}",
            "denial_log_json": "[]",
        },
    )
    return builder


def test_neo4j_search_neighbors_markings_summary(neo4j_session):
    sid = "test-neo4j-phase2"
    delete_snapshot(sid)
    builder = _seed(sid)
    user = next(n for n in builder.snapshot.nodes if "alice" in n)

    hits = neo4j_reads.search_nodes(sid, q="demo", limit=10)
    assert hits is not None
    assert any("demo" in (h.get("display") or "").lower() or "demo" in h["id"].lower() for h in hits)

    nbrs = neo4j_reads.get_neighbors(sid, user, direction="both")
    assert nbrs is not None
    assert any(n["rel_type"] == "READS" and n["direction"] == "out" for n in nbrs)

    marks = neo4j_reads.list_markings(sid)
    assert marks is not None
    assert marks["high_value_count"] >= 1

    summary = neo4j_reads.graph_summary(sid)
    assert summary is not None
    assert summary["node_count"] == 2
    assert summary["edge_count"] == 1

    delete_snapshot(sid)


def test_session_store_uses_neo4j_reads_without_requiring_memory(neo4j_session, tmp_path, monkeypatch):
    sid = "test-neo4j-phase2-store"
    delete_snapshot(sid)
    builder = _seed(sid)

    monkeypatch.setenv("SAMOYED_SESSION_DIR", str(tmp_path))
    store = SessionStore()
    # No disk file, no memory — Neo4j-only session.
    assert store._sessions == {}
    hits = store.search_nodes(sid, q="alice", limit=5)
    assert any("alice" in (h.get("display") or "").lower() for h in hits)

    marks = store.list_markings(sid)
    assert marks["high_value_count"] >= 1

    user = next(n for n in builder.snapshot.nodes if "alice" in n)
    nbrs = store.get_neighbors(sid, user, direction="out")
    assert any(n["rel_type"] == "READS" for n in nbrs)

    payload = store.graph_payload(sid, detail="summary")
    assert payload["access"] == "summary"
    assert payload["node_count"] == 2

    delete_snapshot(sid)
