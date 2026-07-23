from __future__ import annotations

from pathlib import Path

from samoyed.connectors.terraform.importer import import_terraform, parse_tfstate_to_inventory
from samoyed.sessions import SESSION_STORE


FIXTURE = Path(__file__).resolve().parents[1] / "samoyed/fixtures/reports/vpc_peering_cross_account.tfstate"


def test_parse_tfstate_inventory():
    import json

    state = json.loads(FIXTURE.read_text())
    inv = parse_tfstate_to_inventory(state)
    assert len(inv.placements) >= 2
    assert any(p.id == "pcx-devprod" for p in inv.peerings)
    assert any(r.sg_id == "sg-devweb" and "0.0.0.0/0" in r.cidrs for r in inv.sg_rules)


def test_terraform_import_golden_path(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()

    builder, meta = import_terraform(FIXTURE.read_bytes(), session_id="tf-test")
    graph = builder.snapshot

    internet = [
        e
        for e in graph.edges
        if e.rel_type == "CAN_REACH"
        and graph.nodes[e.src_id].props.get("native_id") == "network:internet"
    ]
    assert internet

    peers = [e for e in graph.edges if e.rel_type == "VPC_PEERS"]
    assert peers
    assert any(
        graph.nodes[e.dst_id].props.get("native_id") == "aws:account:222222222222" for e in peers
    )

    bridges = [e for e in graph.edges if e.rel_type == "BRIDGES_TO"]
    assert bridges
    assert meta.get("network_enrichment", {}).get("network_edges", 0) >= 1


def test_fixture_vpc_peering_and_scenario(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()

    record = SESSION_STORE.load_fixture("vpc-peering-aws")
    assert record.metadata.get("source") == "terraform"

    start = SESSION_STORE.find_caller_node(record)
    assert start

    paths = SESSION_STORE.run_scenario(record.session_id, "can-reach-other-accounts")
    assert paths
    assert any(
        any(step.rel_type in {"VPC_PEERS", "BRIDGES_TO"} for step in p.steps) for p in paths
    )


def test_corp_mesh_fixture_has_lbs_buckets_and_peerings(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()

    record = SESSION_STORE.load_fixture("corp-mesh-aws")
    natives = {n.props.get("native_id") for n in record.snapshot.nodes.values()}
    assert any(str(x).startswith("LoadBalancer:") for x in natives)
    assert "S3Bucket:corp-pci-backups" in natives
    assert "S3Bucket:shared-cicd-artifacts" in natives
    assert any(e.rel_type == "VPC_PEERS" for e in record.snapshot.edges)
    # Public ALB / bastion internet exposure
    assert any(
        e.rel_type == "CAN_REACH"
        and record.snapshot.nodes[e.src_id].props.get("native_id") == "network:internet"
        for e in record.snapshot.edges
    )
    paths = SESSION_STORE.run_scenario(record.session_id, "can-reach-other-accounts")
    assert paths


def test_no_intermediate_exposure_nodes_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()

    from samoyed.attack.surface import enrich_attack_surface
    from samoyed.graph.builder import GraphBuilder

    record = SESSION_STORE.load_fixture("corp-mesh-aws")
    g = record.snapshot

    # Exactly one internet node, named "The Internet".
    internet = [n for n in g.nodes.values() if n.props.get("native_id") == "network:internet"]
    assert len(internet) == 1
    assert internet[0].props.get("display_name") == "The Internet"

    # No per-resource intermediate exposure nodes (the old nonsensical model).
    assert not [
        n
        for n in g.nodes.values()
        if str(n.props.get("native_id", "")).startswith("network:exposure:")
    ]
    assert not [
        n
        for n in g.nodes.values()
        if "exposure for" in str(n.props.get("display_name", ""))
    ]

    # Internet connects directly to an exposed resource (e.g. public ALB / bucket).
    internet_id = internet[0].node_id
    direct = [e for e in g.edges if e.src_id == internet_id and e.rel_type == "CAN_REACH"]
    assert direct

    # Re-running enrichment must be idempotent (no feedback-loop growth).
    exposure_nodes_before = sum(
        1 for n in g.nodes.values() if n.props.get("resource_type") == "NetworkExposure"
    )
    b = GraphBuilder(record.session_id)
    b.snapshot = g
    enrich_attack_surface(b)
    enrich_attack_surface(b)
    exposure_nodes_after = sum(
        1 for n in g.nodes.values() if n.props.get("resource_type") == "NetworkExposure"
    )
    assert exposure_nodes_after == exposure_nodes_before == 1


def test_attach_network_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()

    # Minimal session without network, then attach terraform inventory.
    from samoyed.connectors.iam_report.importer import import_iam_report
    import json

    report = {
        "provider": "aws",
        "account_id": "111111111111",
        "caller_arn": "arn:aws:iam::111111111111:user/alice",
        "identities": [
            {
                "arn": "arn:aws:iam::111111111111:user/alice",
                "kind": "User",
                "is_caller": True,
            }
        ],
        "resources": [
            {
                "id": "EC2Instance:i-devbastion01",
                "concept": "RuntimeBinding",
                "type": "EC2Instance",
                "vpc_id": "vpc-dev001",
                "sg_ids": ["sg-devweb"],
                "public_ip": "203.0.113.10",
                "private_ips": ["10.0.1.10"],
                "account_id": "111111111111",
            }
        ],
        "grants": [],
    }
    record = SESSION_STORE.create_import_session("iam-report", json.dumps(report))
    before = len([e for e in record.snapshot.edges if e.rel_type == "VPC_PEERS"])
    result = SESSION_STORE.attach_network_inventory(
        record.session_id,
        FIXTURE.read_bytes(),
        connector_id="terraform",
    )
    after = len([e for e in record.snapshot.edges if e.rel_type == "VPC_PEERS"])
    assert after >= before
    assert result.get("network_enrichment")
