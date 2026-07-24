from __future__ import annotations

import json
from pathlib import Path

from samoyed.connectors.terraform.importer import import_terraform, parse_tfstate_to_inventory
from samoyed.fixtures.registry import get_fixture, fixture_path
from samoyed.path_engine.search import find_attack_paths
from samoyed.sessions import SESSION_STORE


FIXTURE = Path(__file__).resolve().parents[1] / "samoyed/fixtures/reports/corp_mesh_azure.tfstate"


def test_azure_tfstate_inventory_and_executes_as(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()

    inventory = parse_tfstate_to_inventory(json.loads(FIXTURE.read_text()))
    assert inventory.provider == "azure"
    assert inventory.peerings
    assert any(p.resource_type == "AzureVM" for p in inventory.placements) or inventory.peerings

    builder, meta = import_terraform(FIXTURE.read_bytes(), session_id="azure-terraform-test")
    natives = {node.props.get("native_id") for node in builder.snapshot.nodes.values()}
    assert meta["provider"] == "azure"
    assert "KeyVaultSecret:corp-kv-pci/customer-pii-export" in natives
    assert "azure:managedidentity:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in natives
    assert any(edge.rel_type == "EXECUTES_AS" for edge in builder.snapshot.edges)
    assert len(builder.snapshot.nodes) >= 6


def test_corp_mesh_azure_fixture_registered():
    assert fixture_path("corp-mesh-azure").is_file()
    assert get_fixture("corp-mesh-azure").connector == "terraform"


def test_corp_mesh_azure_attack_path_to_crown_jewel(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()

    record = SESSION_STORE.load_fixture("corp-mesh-azure")
    snapshot = record.snapshot
    start = SESSION_STORE.find_caller_node(record)
    assert start

    target = next(
        nid
        for nid, n in snapshot.nodes.items()
        if n.props.get("native_id") == "KeyVaultSecret:corp-kv-pci/customer-pii-export"
        or n.props.get("name") == "customer-pii-export"
    )
    paths = find_attack_paths(snapshot, start_node_id=start, end_node_id=target, max_depth=10)
    assert paths, "bastion/caller should reach Key Vault crown jewel via MI chain"
    assert len(paths[0].steps) >= 3
