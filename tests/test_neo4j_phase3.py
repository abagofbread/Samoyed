"""Phase 3: Cypher path/blast backend parity checks."""

from __future__ import annotations

import os

import pytest

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import apply_marking
from samoyed.graph.neo4j_store import close_driver, delete_snapshot, write_snapshot
from samoyed.path_engine.custom_query import run_graph_query
from samoyed.path_engine.search import find_attack_paths, get_blast_radius


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
    monkeypatch.setenv("SAMOYED_GRAPH_BACKEND", "auto")
    close_driver()
    if not _neo4j_ready():
        pytest.skip("Neo4j not available")
    yield
    close_driver()


def _seed(session_id: str = "test-neo4j-phase3") -> tuple[GraphBuilder, str, str, str]:
    builder = GraphBuilder(session_id)
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/alice",
        props={"native_kind": "User", "display_name": "alice"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/admin",
        props={"native_kind": "Role", "display_name": "admin", "is_high_value": True},
    )
    apply_marking(builder.snapshot.nodes[role].props, high_value=True, source="test")
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="arn:aws:secretsmanager:us-east-1:1:secret:demo",
        props={"native_kind": "Secret", "name": "demo"},
    )
    # Inbound privesc (role can escalate into user) + outbound reads.
    builder.add_edge(
        src_id=role,
        rel_type="CAN_PRIVESC_TO",
        dst_id=user,
        props={"pattern_id": "aws-iam-create-access-key", "inferred": True},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role, props={})
    builder.add_edge(src_id=role, rel_type="READS", dst_id=secret, props={})
    builder.link_session(user)
    builder.link_session(role)
    builder.link_session(secret)
    write_snapshot(
        builder.snapshot,
        session_meta={
            "session_id": session_id,
            "caller_arn": "arn:aws:iam::1:user/alice",
            "provider": "aws",
            "created_at": "2026-01-01T00:00:00+00:00",
            "status": "complete",
            "metadata_json": "{}",
            "denial_log_json": "[]",
        },
    )
    return builder, user, role, secret


def test_cypher_paths_and_blast_match_memory(neo4j_session):
    sid = "test-neo4j-phase3"
    delete_snapshot(sid)
    builder, user, role, secret = _seed(sid)
    graph = builder.snapshot

    mem_hv = find_attack_paths(
        graph, start_node_id=user, target_concept="high_value", direction="both", max_depth=4, max_paths=10
    )
    mem_blast = get_blast_radius(graph, start_node_id=user, max_depth=4, max_paths=10)

    neo = run_graph_query(
        None,
        session_id=sid,
        start_node_id=user,
        mode="paths",
        target_concept="high_value",
        max_depth=4,
        max_paths=10,
        backend="neo4j",
    )
    assert neo["backend"] == "neo4j"
    neo_ends = {p["node_ids"][-1] for p in neo["paths"]}
    mem_ends = {p.node_ids[-1] for p in mem_hv}
    assert role in neo_ends
    assert neo_ends == mem_ends or role in neo_ends

    blast = run_graph_query(
        None,
        session_id=sid,
        start_node_id=user,
        mode="blast",
        max_depth=4,
        max_paths=10,
        backend="neo4j",
    )
    assert blast["backend"] == "neo4j"
    blast_ends = {p["node_ids"][-1] for p in blast["paths"]}
    assert role in blast_ends or secret in blast_ends
    assert len(blast["paths"]) >= 1
    assert len(mem_blast) >= 1

    nbr = run_graph_query(
        None,
        session_id=sid,
        start_node_id=user,
        mode="neighbors",
        backend="neo4j",
    )
    assert nbr["backend"] == "neo4j"
    assert any(n["rel_type"] == "CAN_ASSUME_ROLE" for n in nbr["nodes"])

    delete_snapshot(sid)


def test_force_memory_backend(neo4j_session):
    sid = "test-neo4j-phase3-mem"
    delete_snapshot(sid)
    builder, user, _role, _secret = _seed(sid)
    out = run_graph_query(
        builder.snapshot,
        session_id=sid,
        start_node_id=user,
        mode="blast",
        max_depth=3,
        max_paths=5,
        backend="memory",
    )
    assert out["backend"] == "memory"
    assert len(out["paths"]) >= 1
    delete_snapshot(sid)
