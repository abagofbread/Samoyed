from __future__ import annotations

from pathlib import Path

from samoyed.connectors.bloodhound.importer import import_bloodhound
from samoyed.connectors.bloodhound.parse import parse_bloodhound_payload
from samoyed.path_engine.search import find_attack_paths
from samoyed.sessions import SESSION_STORE

DATA = Path(__file__).parent / "data" / "bloodhound"


def test_sharphound_sessions_admin_import(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (DATA / "sharphound_sessions_admin.json").read_bytes()
    record = SESSION_STORE.create_import_session("bloodhound", payload, session_id="sh-sessions")
    assert record.metadata["source"] == "bloodhound"
    native_ids = {n.props.get("native_id") for n in record.snapshot.nodes.values()}
    assert any(str(i).startswith("ad:computer:") for i in native_ids)
    assert any(str(i).startswith("ad:user:") for i in native_ids)
    rels = {e.rel_type for e in record.snapshot.edges}
    assert "CONTROLS" in rels  # AdminTo
    assert "CAN_STEAL_CREDS_FROM" in rels
    assert "MEMBER_OF" in rels
    assert not any(r.startswith("AZ") for r in rels)


def test_sharphound_acl_forcechange_and_dcsync(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (DATA / "sharphound_acl_privesc.json").read_bytes()
    builder, _meta = import_bloodhound(payload, session_id="sh-acl")
    mech = {(e.rel_type, (e.props or {}).get("mechanism")) for e in builder.snapshot.edges}
    assert ("CAN_PRIVESC_TO", "forcechangepassword") in mech or any(
        e.rel_type == "CAN_PRIVESC_TO" and "forcechange" in str((e.props or {}).get("mechanism", "")).lower()
        for e in builder.snapshot.edges
    )
    assert any(
        e.rel_type == "CAN_PRIVESC_TO" and (e.props or {}).get("mechanism") == "dcsync"
        for e in builder.snapshot.edges
    )


def test_hybrid_mimikatz_entra_path_len(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = (DATA / "hybrid_synced_mimikatz.json").read_bytes()
    record = SESSION_STORE.create_import_session(
        "bloodhound",
        payload,
        session_id="hybrid-mimikatz",
    )
    # Start at compromised host (HasSession computer).
    start = SESSION_STORE.find_host_node(record) or next(
        nid
        for nid, n in record.snapshot.nodes.items()
        if n.props.get("native_kind") == "CompromisedHost"
        or str(n.props.get("native_id") or "").startswith("ad:computer:")
    )
    target = next(
        nid
        for nid, n in record.snapshot.nodes.items()
        if n.props.get("native_id") == "azure:keyvault:eeeeeeee-0000-0000-0000-000000000030"
        or n.props.get("name") == "corp-kv-prod"
    )
    paths = find_attack_paths(record.snapshot, start_node_id=start, end_node_id=target, max_depth=10)
    assert paths, "WS01 HasSession → AD bob → synced Entra → KV Readers → Key Vault"
    assert max(len(p.steps) for p in paths) >= 3
    steal = [
        e
        for e in record.snapshot.edges
        if e.rel_type == "CAN_STEAL_CREDS_FROM"
        and (e.props or {}).get("mechanism") == "lsass-mimikatz"
    ]
    assert steal
    assert not any(e.rel_type.startswith("AZ") for e in record.snapshot.edges)


def test_hybrid_fixture_registered(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("hybrid-mimikatz-entra", session_id="fixture-hybrid")
    assert record.metadata.get("source") == "bloodhound"
    assert any(e.rel_type == "CAN_ASSUME_ROLE" and (e.props or {}).get("mechanism") == "synced-identity" for e in record.snapshot.edges)


def test_ce_parser_extracts_sessions():
    data = (DATA / "sharphound_sessions_admin.json").read_text()
    import json

    parsed = parse_bloodhound_payload(json.loads(data))
    kinds = {e.kind for e in parsed.edges}
    assert "HasSession" in kinds
    assert "AdminTo" in kinds
    assert "MemberOf" in kinds
    assert len(parsed.nodes) >= 4
