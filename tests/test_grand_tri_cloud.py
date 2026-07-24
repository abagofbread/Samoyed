"""Grand tri-cloud lab: corp-mesh-aws patient zero + GCP/Azure bridges + autoload."""

from __future__ import annotations

from pathlib import Path

from samoyed.connectors.terraform.autoload import discover_companion_enrichments
from samoyed.fixtures.loader import load_fixture_session
from samoyed.fixtures.registry import fixture_lab_path, get_fixture
from samoyed.path_engine.search import find_attack_paths

LAB = Path(__file__).resolve().parents[1] / "samoyed" / "fixtures" / "labs" / "grand-tri-cloud"


def _native(record, native_id: str) -> str:
    for node_id, node in record.snapshot.nodes.items():
        if node.props.get("native_id") == native_id:
            return node_id
    raise AssertionError(f"missing native_id {native_id}")


def test_fixture_registered_as_lab_dir():
    spec = get_fixture("grand-tri-cloud")
    assert spec.lab_dir == "grand-tri-cloud"
    assert fixture_lab_path("grand-tri-cloud") == LAB
    assert (LAB / "aws" / "enrichment.json").is_file()
    assert (LAB / "gcp" / "terraform.tfstate").is_file()
    assert (LAB / "azure" / "terraform.tfstate").is_file()


def test_companion_enrichment_discovery():
    found = discover_companion_enrichments(LAB)
    assert len(found) == 3
    assert {p.name for p in found} == {"enrichment.json"}
    assert {p.parent.name for p in found} == {"aws", "gcp", "azure"}


def test_grand_tri_cloud_paths_boundaries_and_autoload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = load_fixture_session("grand-tri-cloud", session_id="grand-one")

    assert record.metadata.get("companion_enrichments")
    assert len(record.metadata["companion_enrichments"]) == 3
    assert sum(int(r.get("materials_applied") or 0) for r in record.metadata["companion_enrichments"]) >= 4

    natives = {n.props.get("native_id") for n in record.snapshot.nodes.values()}
    assert "aws:vpc:vpc-dmz001" in natives
    assert "gcp:vpc:projects/proj-app/global/networks/app" in natives
    assert any(str(n).startswith("azure:vnet:") for n in natives)
    assert any(str(n).startswith("aws:subnet:") for n in natives)
    assert "aws:account:111111111111" in natives
    assert "gcp:project:proj-app" in natives
    assert any(str(n).startswith("azure:subscription:") for n in natives)
    assert "S3Bucket:corp-decoy-cloudtrail-archive" in natives
    assert "ExternalService:stripe-test-mode-deadend" in natives
    assert "decoy-metrics@proj-staging.iam.gserviceaccount.com" in natives

    assert sum(1 for e in record.snapshot.edges if e.rel_type == "HOSTED_IN") >= 20
    assert sum(1 for e in record.snapshot.edges if e.rel_type == "VPC_PEERS") >= 1
    assert sum(1 for e in record.snapshot.edges if e.rel_type == "BRIDGES_TO") >= 1

    # AWS → GCP crown jewel (cloud + project boundaries via identity hops).
    start = _native(record, "arn:aws:iam::111111111111:role/web-role")
    crown = _native(record, "GCSBucket:corp-pci-crown-jewel")
    paths = find_attack_paths(
        record.snapshot,
        start_node_id=start,
        end_node_id=crown,
        max_depth=8,
        max_paths=3,
    )
    assert paths, "web-role → bastion → GCP app-deploy → cloudbuild → pci-reader → crown GCS"
    rels = [s.rel_type for s in paths[0].steps]
    assert rels[0] == "CAN_ASSUME_ROLE"
    assert "HAS_MATERIAL" in rels and "UNLOCKS" in rels
    assert rels.count("CAN_ASSUME_ROLE") >= 3
    assert rels[-1] == "READS"
    assert len(paths[0].steps) >= 5

    # AWS app-worker → weak Azure SP → WebApp control (subscription hop via unlock).
    worker = _native(record, "EC2Instance:i-appworker01")
    sp = _native(record, "azure:serviceprincipal:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    unlock = find_attack_paths(
        record.snapshot,
        start_node_id=worker,
        end_node_id=sp,
        max_depth=3,
        max_paths=2,
    )
    assert unlock and [s.rel_type for s in unlock[0].steps] == ["HAS_MATERIAL", "UNLOCKS"]
    assert any(
        e.rel_type == "CONTROLS"
        and e.src_id == sp
        and "app-corp-api" in str(record.snapshot.nodes[e.dst_id].props.get("native_id") or "")
        for e in record.snapshot.edges
    )
    secret = _native(record, "KeyVaultSecret:corp-kv-pci/customer-pii-export")
    az_paths = find_attack_paths(
        record.snapshot,
        start_node_id=sp,
        end_node_id=secret,
        max_depth=5,
        max_paths=2,
    )
    assert az_paths and len(az_paths[0].steps) >= 2
