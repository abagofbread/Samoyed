"""Tests for NetworkBoundary synthesis (VPC/subnet + nested HOSTED_IN)."""

from __future__ import annotations

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder, stable_id
from samoyed.network.boundaries import synthesize_network_boundaries
from samoyed.network.enrich import enrich_network_reachability
from samoyed.network.model import NetworkInventory, NetworkPlacement, PeeringLink, SgIngressRule


def _inventory_with_subnets() -> NetworkInventory:
    return NetworkInventory(
        provider="aws",
        source="test",
        placements=[
            NetworkPlacement(
                native_id="EC2Instance:i-web",
                account_id="111111111111",
                vpc_id="vpc-dmz",
                subnet_ids=["subnet-dmz-a"],
                private_ips=["10.0.1.10"],
                sg_ids=["sg-web"],
                resource_type="EC2Instance",
            ),
            NetworkPlacement(
                native_id="EC2Instance:i-db",
                account_id="111111111111",
                vpc_id="vpc-dmz",
                subnet_ids=["subnet-dmz-b"],
                private_ips=["10.0.2.20"],
                sg_ids=["sg-db"],
                resource_type="EC2Instance",
            ),
        ],
        vpc_cidrs={"vpc-dmz": ["10.0.0.0/16"]},
        sg_rules=[
            SgIngressRule(sg_id="sg-web", cidrs=["0.0.0.0/0"]),
            SgIngressRule(sg_id="sg-db", cidrs=["10.0.1.0/24"]),
        ],
    )


def _seed_compute(builder: GraphBuilder, *native_ids: str) -> dict[str, str]:
    ids: dict[str, str] = {}
    for native_id in native_ids:
        ids[native_id] = builder.add_concept_node(
            concept_type=ConceptType.RUNTIME_BINDING,
            native_id=native_id,
            props={"display_name": native_id, "resource_type": "EC2Instance"},
        )
    return ids


def _has_edge(graph, src: str, rel: str, dst: str) -> bool:
    for dst_id, edge_rel, _props in graph.adjacency.get(src, []):
        if edge_rel == rel and dst_id == dst:
            return True
    return False


def test_synthesize_vpc_subnet_and_hosted_in_chain():
    builder = GraphBuilder("sess-boundaries")
    compute = _seed_compute(builder, "EC2Instance:i-web", "EC2Instance:i-db")
    inv = _inventory_with_subnets()

    stats = synthesize_network_boundaries(builder, inv)
    assert stats["vpc_boundaries"] == 1
    assert stats["subnet_boundaries"] == 2
    assert stats["hosted_in_edges"] >= 4  # 2 subnet→vpc, vpc→account, 2 compute→subnet

    vpc_id = stable_id("NetworkBoundary", "aws:vpc:vpc-dmz")
    subnet_a = stable_id("NetworkBoundary", "aws:subnet:subnet-dmz-a")
    subnet_b = stable_id("NetworkBoundary", "aws:subnet:subnet-dmz-b")
    account_id = stable_id("ScopeBoundary", "aws:account:111111111111")

    assert vpc_id in builder.snapshot.nodes
    assert builder.snapshot.nodes[vpc_id].label == "NetworkBoundary"
    assert builder.snapshot.nodes[vpc_id].props["boundary_kind"] == "vpc"
    assert builder.snapshot.nodes[vpc_id].props["cidrs"] == ["10.0.0.0/16"]

    assert builder.snapshot.nodes[subnet_a].props["boundary_kind"] == "subnet"
    assert builder.snapshot.nodes[account_id].props["boundary_kind"] == "account"

    assert _has_edge(builder.snapshot, subnet_a, "HOSTED_IN", vpc_id)
    assert _has_edge(builder.snapshot, subnet_b, "HOSTED_IN", vpc_id)
    assert _has_edge(builder.snapshot, vpc_id, "HOSTED_IN", account_id)
    assert _has_edge(builder.snapshot, compute["EC2Instance:i-web"], "HOSTED_IN", subnet_a)
    assert _has_edge(builder.snapshot, compute["EC2Instance:i-db"], "HOSTED_IN", subnet_b)


def test_synthesize_is_idempotent():
    builder = GraphBuilder("sess-idempotent")
    _seed_compute(builder, "EC2Instance:i-web", "EC2Instance:i-db")
    inv = _inventory_with_subnets()

    first = synthesize_network_boundaries(builder, inv)
    edge_count = len(builder.snapshot.edges)
    node_count = len(builder.snapshot.nodes)

    second = synthesize_network_boundaries(builder, inv)
    assert second["vpc_boundaries"] == 0
    assert second["subnet_boundaries"] == 0
    assert second["hosted_in_edges"] == 0
    assert len(builder.snapshot.edges) == edge_count
    assert len(builder.snapshot.nodes) == node_count
    assert first["vpc_boundaries"] == 1


def test_vpc_without_subnet_hosts_compute_directly():
    builder = GraphBuilder("sess-vpc-only")
    compute = _seed_compute(builder, "EC2Instance:i-solo")
    inv = NetworkInventory(
        placements=[
            NetworkPlacement(
                native_id="EC2Instance:i-solo",
                account_id="111111111111",
                vpc_id="vpc-solo",
                private_ips=["10.9.0.1"],
                sg_ids=["sg-solo"],
            )
        ],
        vpc_cidrs={"vpc-solo": ["10.9.0.0/16"]},
    )
    synthesize_network_boundaries(builder, inv)
    vpc_id = stable_id("NetworkBoundary", "aws:vpc:vpc-solo")
    assert _has_edge(builder.snapshot, compute["EC2Instance:i-solo"], "HOSTED_IN", vpc_id)


def test_enrich_network_reachability_creates_boundaries():
    builder = GraphBuilder("sess-enrich")
    _seed_compute(builder, "EC2Instance:i-web", "EC2Instance:i-db")
    stats = enrich_network_reachability(builder, _inventory_with_subnets())
    assert stats["vpc_boundaries"] == 1
    assert stats["subnet_boundaries"] == 2
    assert stats["hosted_in_edges"] >= 4
    assert any(
        n.label == "NetworkBoundary" and n.props.get("boundary_kind") == "vpc"
        for n in builder.snapshot.nodes.values()
    )


def test_cross_account_peer_still_creates_account_boundary():
    builder = GraphBuilder("sess-xa")
    _seed_compute(builder, "EC2Instance:i-dev")
    inv = NetworkInventory(
        placements=[
            NetworkPlacement(
                native_id="EC2Instance:i-dev",
                account_id="111111111111",
                vpc_id="vpc-dev",
                subnet_ids=["subnet-dev"],
                private_ips=["10.0.1.10"],
                public_ip="203.0.113.10",
                sg_ids=["sg-dev"],
            ),
            NetworkPlacement(
                native_id="EC2Instance:i-prod",
                account_id="222222222222",
                vpc_id="vpc-prod",
                subnet_ids=["subnet-prod"],
                private_ips=["10.1.2.20"],
                sg_ids=["sg-prod"],
            ),
        ],
        peerings=[
            PeeringLink(
                id="pcx-1",
                status="active",
                local_vpc_id="vpc-dev",
                local_account_id="111111111111",
                remote_vpc_id="vpc-prod",
                remote_account_id="222222222222",
                local_cidrs=["10.0.0.0/16"],
                remote_cidrs=["10.1.0.0/16"],
            )
        ],
        sg_rules=[
            SgIngressRule(sg_id="sg-dev", cidrs=["0.0.0.0/0"]),
            SgIngressRule(sg_id="sg-prod", cidrs=["10.0.0.0/16"]),
        ],
        vpc_cidrs={"vpc-dev": ["10.0.0.0/16"], "vpc-prod": ["10.1.0.0/16"]},
    )
    enrich_network_reachability(builder, inv)
    prod_account = stable_id("ScopeBoundary", "aws:account:222222222222")
    assert prod_account in builder.snapshot.nodes
    assert builder.snapshot.nodes[prod_account].props.get("boundary_kind") == "account"
    assert any(e.rel_type == "VPC_PEERS" for e in builder.snapshot.edges)
