from __future__ import annotations

from pathlib import Path

from samoyed.connectors.terraform.importer import import_terraform, parse_tfstate_to_inventory
from samoyed.fixtures.registry import get_fixture, fixture_path
from samoyed.sessions import SESSION_STORE


FIXTURE = Path(__file__).resolve().parents[1] / "samoyed/fixtures/reports/corp_mesh_gcp.tfstate"


def test_gcp_tfstate_network_and_identity_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()

    inventory = parse_tfstate_to_inventory(__import__("json").loads(FIXTURE.read_text()))
    assert inventory.provider == "gcp"
    assert any(p.resource_type == "GCEInstance" and p.account_id == "proj-dmz" for p in inventory.placements)
    assert inventory.peerings

    builder, meta = import_terraform(FIXTURE.read_bytes(), session_id="gcp-terraform-test")
    natives = {node.props.get("native_id") for node in builder.snapshot.nodes.values()}
    assert meta["provider"] == "gcp"
    assert "GCSBucket:corp-pci-crown-jewel" in natives
    assert "bastion@proj-dmz.iam.gserviceaccount.com" in natives
    assert any(edge.rel_type == "EXECUTES_AS" for edge in builder.snapshot.edges)
    assert any(edge.rel_type == "CAN_ASSUME_ROLE" for edge in builder.snapshot.edges)


def test_gcp_and_intercloud_fixtures_are_registered():
    for fixture_id in ("corp-mesh-gcp", "lab-gcp", "intercloud-host-pivot", "wif-aws-gcp"):
        assert fixture_path(fixture_id).is_file()
        assert get_fixture(fixture_id).id == fixture_id
