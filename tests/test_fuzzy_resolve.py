from __future__ import annotations

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.fuzzy import (
    fuzzy_match_nodes,
    fuzzy_resolve_node,
    leaf_name,
    prefer_concepts_for_material,
)
from samoyed.graph.refs import resolve_node_ref


def test_leaf_name_strips_secrets_manager_suffix():
    assert leaf_name("RDS_CREDS-AbCdEf") == "RDS_CREDS"
    assert (
        leaf_name("arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS-AbCdEf")
        == "RDS_CREDS"
    )
    assert leaf_name("arn:aws:iam::1:role/ecs-task-role") == "ecs-task-role"


def test_fuzzy_resolves_secret_arn_suffix_without_name_prop():
    builder = GraphBuilder("fuzzy-secret")
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS-aaaaaa",
        props={
            "native_kind": "Secret",
            "arn": "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS-aaaaaa",
        },
    )
    # Wildcard inventory stub must not win
    builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:rds!*",
        props={"native_kind": "Secret", "native_id": "Secret:arn:aws:secretsmanager:us-east-1:1:secret:rds!*"},
    )
    assert resolve_node_ref(builder.snapshot, "RDS_CREDS") == secret
    assert fuzzy_resolve_node(builder.snapshot, "RDS_CREDS") == secret


def test_fuzzy_resolves_role_and_db_names():
    builder = GraphBuilder("fuzzy-names")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/ecs-instance-role"},
    )
    db = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="arn:aws:rds:us-east-1:1:db:aws-goat-db",
        props={
            "native_kind": "DBInstance",
            "db_instance_identifier": "aws-goat-db",
            "arn": "arn:aws:rds:us-east-1:1:db:aws-goat-db",
        },
    )
    assert resolve_node_ref(builder.snapshot, "ecs-instance-role") == role
    assert resolve_node_ref(
        builder.snapshot,
        "aws-goat-db",
        prefer_concepts=prefer_concepts_for_material("database_connection_string"),
    ) == db


def test_fuzzy_rejects_wildcard_stubs():
    builder = GraphBuilder("fuzzy-stub")
    builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS*",
        props={
            "native_kind": "Secret",
            "native_id": "Secret:arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS*",
            "name": "RDS_CREDS*",
        },
    )
    assert resolve_node_ref(builder.snapshot, "RDS_CREDS") is None
    assert fuzzy_match_nodes(builder.snapshot, "RDS_CREDS") == []


def test_fuzzy_ambiguous_returns_none():
    builder = GraphBuilder("fuzzy-ambig")
    builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role-a",
        props={"native_kind": "Role", "name": "ecs-task-role-a"},
    )
    builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role-b",
        props={"native_kind": "Role", "name": "ecs-task-role-b"},
    )
    # Shared substring / token overlap without a clear unique winner
    assert fuzzy_resolve_node(builder.snapshot, "ecs-task-role") is None
    assert fuzzy_resolve_node(builder.snapshot, "ecs-task-role", allow_ambiguous=True) is not None


def test_session_resolve_start_uses_fuzzy(tmp_path, monkeypatch):
    """Path/mark start resolution shares enrichment fuzzy matching."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SAMOYED_SESSIONS_DIR", str(tmp_path / "sessions"))

    from datetime import datetime, timezone

    from samoyed.cloud.concepts import CloudProvider
    from samoyed.sessions import SESSION_STORE, SessionRecord

    builder = GraphBuilder("fuzzy-session")
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS-AbCdEf",
        props={
            "native_kind": "Secret",
            "arn": "arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS-AbCdEf",
        },
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/ecs-instance-role",
            "name": "ecs-instance-role",
            "is_caller": True,
        },
    )
    builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:rds!*",
        props={
            "native_kind": "Secret",
            "native_id": "Secret:arn:aws:secretsmanager:us-east-1:1:secret:rds!*",
        },
    )

    sid = "fuzzy-resolve-session-test"
    SESSION_STORE._sessions[sid] = SessionRecord(
        session_id=sid,
        provider=CloudProvider.AWS,
        caller_arn="arn:aws:iam::1:role/ecs-instance-role",
        scope_id="aws:1",
        created_at=datetime.now(timezone.utc).isoformat(),
        status="ready",
        snapshot=builder.snapshot,
    )
    monkeypatch.setattr(SESSION_STORE, "_persist", lambda *_a, **_k: None)
    monkeypatch.setattr("samoyed.sessions.write_snapshot", lambda *_a, **_k: None)

    assert SESSION_STORE.resolve_start_node(sid, "ecs-instance-role") == role
    assert SESSION_STORE.resolve_start_node(sid, "RDS_CREDS") == secret
    assert SESSION_STORE.resolve_end_node(sid, "RDS_CREDS") == secret
    marked = SESSION_STORE.mark_nodes(sid, ["RDS_CREDS"], high_value=True, source="test")
    assert marked["marked"][0]["node_id"] == secret
    assert marked["unresolved"] == []
