from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.connectors.bloodhound.importer import import_bloodhound
from samoyed.connectors.registry import import_report
from samoyed.path_engine.search import find_attack_paths
from samoyed.sessions import SESSION_STORE

DATA = Path(__file__).parent / "data" / "bloodhound"
client = TestClient(app)


def test_azurehound_appadmin_to_global_admin_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (DATA / "azurehound_entra_addsecret.json").read_bytes()
    record = SESSION_STORE.create_import_session(
        "bloodhound",
        payload,
        caller_arn="azure:user:aaaaaaaa-0000-0000-0000-000000000003",
        session_id="bh-entra-addsecret",
    )
    assert record.metadata.get("source") == "bloodhound"
    assert record.metadata.get("provider") == "azure"

    rels = {e.rel_type for e in record.snapshot.edges}
    assert not any(r.startswith("AZ") for r in rels)
    assert "MEMBER_OF" in rels
    assert "CAN_ASSUME_ROLE" in rels
    assert "CAN_PRIVESC_TO" in rels

    start = SESSION_STORE.find_caller_node(record)
    assert start
    target = next(
        nid
        for nid, n in record.snapshot.nodes.items()
        if n.props.get("native_id") == "azure:role:dddddddd-0000-0000-0000-000000000090"
        or "Global Administrator" in str(n.props.get("display_name") or "")
    )
    paths = find_attack_paths(record.snapshot, start_node_id=start, end_node_id=target, max_depth=8)
    assert paths, "App Admin member should reach Global Admin via add-secret → SP → grant-role"
    assert max(len(p.steps) for p in paths) >= 3


def test_unknown_and_azcontains_ignored(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (DATA / "azurehound_entra_addsecret.json").read_bytes()
    builder, meta = import_report("bloodhound", payload, session_id="bh-ignore")
    rels = {e.rel_type for e in builder.snapshot.edges}
    assert "AZContains" not in rels
    assert "TotallyUnknownKind" not in rels
    assert not any(str(r).startswith("AZ") for r in rels)
    assert meta.get("bh_edge_count", 0) >= 4


def test_bloodhound_fixture_and_api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("bloodhound-entra-lab", session_id="fixture-bh-entra")
    assert record.metadata.get("source") == "bloodhound"
    assert any(
        e.rel_type == "CAN_ASSUME_ROLE" and (e.props or {}).get("mechanism") == "add-secret"
        for e in record.snapshot.edges
    )

    payload = (DATA / "azurehound_entra_addsecret.json").read_bytes()
    res = client.post(
        "/api/sessions/bloodhound",
        data={"caller_arn": "azure:user:aaaaaaaa-0000-0000-0000-000000000003"},
        files={"file": ("entra.json", payload, "application/json")},
    )
    assert res.status_code == 200
    assert res.json()["metadata"]["source"] == "bloodhound"


def test_import_bloodhound_direct(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (DATA / "azurehound_entra_addsecret.json").read_text()
    builder, meta = import_bloodhound(payload, session_id="bh-direct")
    assert meta["source"] == "bloodhound"
    assert meta["artifact_count"] >= 4
