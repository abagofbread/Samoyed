from __future__ import annotations

from samoyed.network.model import NetworkInventory, NetworkPlacement, PeeringLink, SgIngressRule
from samoyed.network.reachability import evaluate_reachability


def _base_inventory() -> NetworkInventory:
    return NetworkInventory(
        provider="aws",
        source="test",
        placements=[
            NetworkPlacement(
                native_id="EC2Instance:i-dev",
                account_id="111111111111",
                vpc_id="vpc-dev",
                private_ips=["10.0.1.10"],
                public_ip="203.0.113.10",
                sg_ids=["sg-dev"],
                resource_type="EC2Instance",
            ),
            NetworkPlacement(
                native_id="EC2Instance:i-prod",
                account_id="222222222222",
                vpc_id="vpc-prod",
                private_ips=["10.1.2.20"],
                sg_ids=["sg-prod"],
                resource_type="EC2Instance",
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


def test_internet_ingress_open_sg():
    intents = evaluate_reachability(_base_inventory())
    internet = [
        i
        for i in intents
        if i.rel_type == "CAN_REACH"
        and i.src_native_id == "network:internet"
        and i.dst_native_id == "EC2Instance:i-dev"
    ]
    assert internet
    assert internet[0].mechanism == "internet-ingress"


def test_cross_account_vpc_peers_and_bridges():
    intents = evaluate_reachability(_base_inventory())
    peers = [i for i in intents if i.rel_type == "VPC_PEERS"]
    bridges = [i for i in intents if i.rel_type == "BRIDGES_TO"]
    # Cross-account reach is modeled through the account boundary node, NOT via a
    # direct compute->compute CAN_REACH edge that skips the boundary.
    direct = [
        i
        for i in intents
        if i.rel_type == "CAN_REACH"
        and i.src_native_id == "EC2Instance:i-dev"
        and i.dst_native_id == "EC2Instance:i-prod"
    ]
    assert any(i.dst_native_id == "aws:account:222222222222" for i in peers)
    assert any(i.dst_native_id == "EC2Instance:i-prod" for i in bridges)
    assert not direct


def test_inactive_peering_ignored():
    inv = _base_inventory()
    inv.peerings[0].status = "pending-acceptance"
    intents = evaluate_reachability(inv)
    assert not any(i.rel_type == "VPC_PEERS" for i in intents)


def test_same_vpc_sg_ref():
    inv = NetworkInventory(
        placements=[
            NetworkPlacement(
                native_id="EC2Instance:a",
                account_id="1",
                vpc_id="vpc-1",
                private_ips=["10.0.0.1"],
                sg_ids=["sg-a"],
            ),
            NetworkPlacement(
                native_id="EC2Instance:b",
                account_id="1",
                vpc_id="vpc-1",
                private_ips=["10.0.0.2"],
                sg_ids=["sg-b"],
            ),
        ],
        sg_rules=[SgIngressRule(sg_id="sg-b", referenced_sg_ids=["sg-a"])],
        vpc_cidrs={"vpc-1": ["10.0.0.0/16"]},
    )
    intents = evaluate_reachability(inv)
    assert any(
        i.rel_type == "CAN_REACH"
        and i.src_native_id == "EC2Instance:a"
        and i.dst_native_id == "EC2Instance:b"
        for i in intents
    )
