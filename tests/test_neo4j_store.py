"""Neo4j store unit + optional integration tests."""

from __future__ import annotations

import os

import pytest

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph import neo4j_store as store
from samoyed.graph.neo4j_store import (
    close_driver,
    delete_snapshot,
    load_session_meta,
    load_snapshot,
    neo4j_configured,
    run_readonly_cypher,
    write_snapshot,
)


def test_run_readonly_cypher_rejects_writes(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7687")
    with pytest.raises(ValueError, match="Write operations"):
        run_readonly_cypher("CREATE (n:Test {id: 1}) RETURN n")


def test_safe_label_rejects_injection():
    with pytest.raises(ValueError, match="Invalid Neo4j node label"):
        store._safe_label("Identity} DELETE n //")
    with pytest.raises(ValueError, match="Invalid Neo4j relationship type"):
        store._safe_rel("CAN_ASSUME_ROLE]-(x)")


def test_serialize_props_json_encodes_nested():
    out = store._serialize_props({"ok": 1, "nested": {"a": True}, "skip": None})
    assert out["ok"] == 1
    assert out["nested"] == '{"a": true}'
    assert "skip" not in out


def test_deserialize_props_restores_json_blobs():
    raw = {
        "ok": 1,
        "impact_targets": '[{"name": "aws-goat-db", "kind": "db_instance"}]',
        "name_hints": '["RDS_CREDS", "aws-goat-db"]',
        "plain": "Secret:*",
    }
    out = store._deserialize_props(raw)
    assert out["ok"] == 1
    assert out["impact_targets"] == [{"name": "aws-goat-db", "kind": "db_instance"}]
    assert out["name_hints"] == ["RDS_CREDS", "aws-goat-db"]
    assert out["plain"] == "Secret:*"


def _neo4j_ready() -> bool:
    if not os.environ.get("NEO4J_URI"):
        return False
    try:
        driver = store.get_driver()
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
        monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7687")
        monkeypatch.setenv("NEO4J_USER", "neo4j")
        monkeypatch.setenv("NEO4J_PASSWORD", "samoyed-dev")
    close_driver()
    if not _neo4j_ready():
        pytest.skip("Neo4j not available (set NEO4J_URI / start docker compose)")
    yield
    close_driver()


def _sample_builder(session_id: str = "test-neo4j-roundtrip") -> GraphBuilder:
    builder = GraphBuilder(session_id)
    a = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/alice",
        props={"native_kind": "User", "display_name": "alice"},
    )
    b = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="arn:aws:secretsmanager:us-east-1:1:secret:demo",
        props={"native_kind": "Secret", "name": "demo"},
    )
    builder.add_edge(
        src_id=a,
        rel_type="READS",
        dst_id=b,
        props={"action": "secretsmanager:GetSecretValue"},
    )
    # Realistic sessions embed a CollectionSession node + DISCOVERED edges.
    builder.link_session(a)
    builder.link_session(b)
    return builder


def test_write_load_replace_delete_roundtrip(neo4j_session):
    sid = "test-neo4j-roundtrip"
    delete_snapshot(sid)

    builder = _sample_builder(sid)
    meta = {
        "session_id": sid,
        "caller_arn": "arn:aws:iam::1:user/alice",
        "provider": "aws",
        "scope_id": "aws:1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "status": "complete",
        "metadata_json": '{"node_count": 2}',
        "denial_log_json": "[]",
    }
    write_snapshot(builder.snapshot, session_meta=meta)

    loaded = load_snapshot(sid)
    assert loaded is not None
    assert len(loaded.nodes) == 2
    assert len(loaded.edges) == 1
    assert loaded.edges[0].rel_type == "READS"
    assert load_session_meta(sid)["caller_arn"] == "arn:aws:iam::1:user/alice"

    # Replace write drops stale edges/nodes.
    builder2 = GraphBuilder(sid)
    only = builder2.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/bob",
        props={"native_kind": "User"},
    )
    assert only
    write_snapshot(builder2.snapshot, session_meta=meta)
    replaced = load_snapshot(sid)
    assert replaced is not None
    assert len(replaced.nodes) == 1
    assert len(replaced.edges) == 0
    assert any("bob" in (n.props.get("native_id") or "") for n in replaced.nodes.values())

    assert delete_snapshot(sid) is True
    assert load_snapshot(sid) is None


def test_sessions_isolated(neo4j_session):
    a = _sample_builder("test-neo4j-iso-a")
    b = _sample_builder("test-neo4j-iso-b")
    write_snapshot(a.snapshot, session_meta={"session_id": "test-neo4j-iso-a", "provider": "aws"})
    write_snapshot(b.snapshot, session_meta={"session_id": "test-neo4j-iso-b", "provider": "aws"})

    assert delete_snapshot("test-neo4j-iso-a") is True
    assert load_snapshot("test-neo4j-iso-a") is None
    still = load_snapshot("test-neo4j-iso-b")
    assert still is not None
    assert len(still.nodes) == 2
    delete_snapshot("test-neo4j-iso-b")


def test_neo4j_configured_flag(monkeypatch):
    monkeypatch.delenv("NEO4J_URI", raising=False)
    close_driver()
    assert neo4j_configured() is False
    monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7687")
    assert neo4j_configured() is True
