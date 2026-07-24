from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from samoyed.network.model import NetworkInventory, NetworkPlacement, PeeringLink, SgIngressRule

MAX_PAIRWISE_EDGES = 500


@dataclass(frozen=True)
class EdgeIntent:
    rel_type: str
    src_native_id: str
    dst_native_id: str
    mechanism: str
    props: dict[str, Any] = field(default_factory=dict)


def evaluate_reachability(inventory: NetworkInventory) -> list[EdgeIntent]:
    """SG-lite evaluation: internet, same-VPC, and peered-VPC reachability intents."""
    if inventory.is_empty():
        return []

    intents: list[EdgeIntent] = []
    intents.extend(_internet_intents(inventory))
    intents.extend(_same_vpc_intents(inventory))
    intents.extend(_peering_intents(inventory))
    return _dedupe(intents)


def _internet_intents(inventory: NetworkInventory) -> list[EdgeIntent]:
    out: list[EdgeIntent] = []
    for placement in inventory.placements:
        if not _is_internet_exposed(inventory, placement):
            continue
        out.append(
            EdgeIntent(
                rel_type="CAN_REACH",
                src_native_id="network:internet",
                dst_native_id=placement.native_id,
                mechanism="internet-ingress",
                props={
                    "exposure_level": "internet",
                    "sg_ids": list(placement.sg_ids),
                    "public_ip": placement.public_ip,
                },
            )
        )
    return out


def _is_internet_exposed(inventory: NetworkInventory, placement: NetworkPlacement) -> bool:
    if placement.exposed_internet:
        return True
    rules = inventory.ingress_rules_for(placement.sg_ids)
    open_world = any(_rule_allows_internet(r) for r in rules)
    if not open_world:
        return False
    # Prefer public IP when present; Cartography-style exposed_internet already returned above.
    # Open SG alone is enough for attack-path modeling (lightweight).
    return True


def _rule_allows_internet(rule: SgIngressRule) -> bool:
    for cidr in rule.cidrs:
        if cidr in {"0.0.0.0/0", "::/0"}:
            return True
    return False


def _same_vpc_intents(inventory: NetworkInventory) -> list[EdgeIntent]:
    by_vpc: dict[str, list[NetworkPlacement]] = {}
    for p in inventory.placements:
        if not p.vpc_id:
            continue
        by_vpc.setdefault(p.vpc_id, []).append(p)

    out: list[EdgeIntent] = []
    for vpc_id, members in by_vpc.items():
        vpc_cidrs = inventory.vpc_cidrs.get(vpc_id, [])
        for src in members:
            for dst in members:
                if src.native_id == dst.native_id:
                    continue
                if not _sg_allows_source(inventory, src=src, dst=dst, extra_cidrs=vpc_cidrs):
                    continue
                out.append(
                    EdgeIntent(
                        rel_type="CAN_REACH",
                        src_native_id=src.native_id,
                        dst_native_id=dst.native_id,
                        mechanism="sg-lite",
                        props={"vpc_id": vpc_id, "scope": "same-vpc"},
                    )
                )
                if len(out) >= MAX_PAIRWISE_EDGES:
                    return out
    return out


def _peering_intents(inventory: NetworkInventory) -> list[EdgeIntent]:
    out: list[EdgeIntent] = []
    for peering in inventory.peerings:
        if not peering.is_active:
            continue
        out.extend(_intents_for_peering(inventory, peering, reverse=False))
        out.extend(_intents_for_peering(inventory, peering, reverse=True))
        if len(out) >= MAX_PAIRWISE_EDGES:
            break
    return out


def _intents_for_peering(
    inventory: NetworkInventory,
    peering: PeeringLink,
    *,
    reverse: bool,
) -> list[EdgeIntent]:
    if reverse:
        local_vpc, remote_vpc = peering.remote_vpc_id, peering.local_vpc_id
        local_account, remote_account = peering.remote_account_id, peering.local_account_id
        remote_cidrs = peering.local_cidrs
    else:
        local_vpc, remote_vpc = peering.local_vpc_id, peering.remote_vpc_id
        local_account, remote_account = peering.local_account_id, peering.remote_account_id
        remote_cidrs = peering.remote_cidrs

    if not local_vpc or not remote_vpc:
        return []

    local_members = inventory.placements_by_vpc(local_vpc)
    remote_members = inventory.placements_by_vpc(remote_vpc)
    if not local_members:
        return []

    out: list[EdgeIntent] = []
    cross_account = bool(local_account and remote_account and local_account != remote_account)

    if cross_account:
        if (inventory.provider or "aws").lower() == "gcp":
            account_native = f"gcp:project:{remote_account}"
        else:
            account_native = f"aws:account:{remote_account}"
        peers_props = {
            "peering_id": peering.id,
            "local_vpc_id": local_vpc,
            "remote_vpc_id": remote_vpc,
            "remote_account_id": remote_account,
            "local_account_id": local_account,
        }

        # No visibility into the peer account's members (the common cross-account
        # case): record the peering window from every local member into the account
        # boundary. Session grafting can continue the attack path from there.
        if not remote_members:
            for src in local_members:
                out.append(
                    EdgeIntent(
                        rel_type="VPC_PEERS",
                        src_native_id=src.native_id,
                        dst_native_id=account_native,
                        mechanism="vpc-peering",
                        props=dict(peers_props),
                    )
                )
            return out

        # Peer members are visible: model the crossing through the boundary node only:
        #   src -VPC_PEERS-> Account:{id} -BRIDGES_TO-> remote resource.
        # We deliberately do NOT emit a direct src->remote CAN_REACH edge that skips
        # the boundary, and we only assert a crossing when an SG actually permits it.
        for src in local_members:
            reachable = [
                dst
                for dst in remote_members
                if _sg_allows_source(
                    inventory,
                    src=src,
                    dst=dst,
                    extra_cidrs=remote_cidrs or inventory.vpc_cidrs.get(remote_vpc, []),
                )
            ]
            if not reachable:
                continue
            out.append(
                EdgeIntent(
                    rel_type="VPC_PEERS",
                    src_native_id=src.native_id,
                    dst_native_id=account_native,
                    mechanism="vpc-peering",
                    props=dict(peers_props),
                )
            )
            for dst in reachable:
                out.append(
                    EdgeIntent(
                        rel_type="BRIDGES_TO",
                        src_native_id=account_native,
                        dst_native_id=dst.native_id,
                        mechanism="vpc-peering",
                        props={
                            "boundary_crossing": True,
                            "ui_label": "",
                            "peering_id": peering.id,
                            "remote_account_id": remote_account,
                        },
                    )
                )
        return out

    # Same-account peering: direct CAN_REACH between placements when SG allows.
    for src in local_members:
        for dst in remote_members:
            if src.native_id == dst.native_id:
                continue
            if not _sg_allows_source(
                inventory,
                src=src,
                dst=dst,
                extra_cidrs=remote_cidrs or inventory.vpc_cidrs.get(remote_vpc, []),
            ):
                continue
            out.append(
                EdgeIntent(
                    rel_type="CAN_REACH",
                    src_native_id=src.native_id,
                    dst_native_id=dst.native_id,
                    mechanism="sg-lite",
                    props={"scope": "peered-vpc", "peering_id": peering.id},
                )
            )
    return out


def _sg_allows_source(
    inventory: NetworkInventory,
    *,
    src: NetworkPlacement,
    dst: NetworkPlacement,
    extra_cidrs: list[str] | None = None,
) -> bool:
    rules = inventory.ingress_rules_for(dst.sg_ids)
    if not rules:
        # No SG data: conservative allow within known VPC/peering topology only when
        # caller provided extra_cidrs (VPC/peer CIDR context). Prefer explicit rules.
        return False

    src_sgs = set(src.sg_ids)
    for rule in rules:
        # A world-open (0.0.0.0/0) rule means the target is internet-exposed; that
        # is modeled by a single 'The Internet -CAN_REACH-> target' edge. Do NOT
        # additionally manufacture pairwise compute->compute edges for it, or every
        # neighbour lights up an edge into the open target and the graph becomes a
        # meaningless mesh. Pairwise lateral edges require a *scoped* allow below.
        if _rule_allows_internet(rule):
            continue
        if src_sgs & set(rule.referenced_sg_ids):
            return True
        for cidr in rule.cidrs:
            if _ip_in_cidrs(src.private_ips, [cidr]):
                return True
            if extra_cidrs and cidr in extra_cidrs:
                return True
            if extra_cidrs and _cidr_covers_any(cidr, extra_cidrs):
                return True
            # Allow when rule CIDR equals/overlaps source VPC CIDR.
            src_vpc_cidrs = inventory.vpc_cidrs.get(src.vpc_id, [])
            if src_vpc_cidrs and (_cidr_covers_any(cidr, src_vpc_cidrs) or cidr in src_vpc_cidrs):
                return True
    return False


def _ip_in_cidrs(ips: list[str], cidrs: list[str]) -> bool:
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for cidr in cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    return False


def _cidr_covers_any(rule_cidr: str, candidate_cidrs: list[str]) -> bool:
    try:
        network = ipaddress.ip_network(rule_cidr, strict=False)
    except ValueError:
        return False
    for cidr in candidate_cidrs:
        try:
            other = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if other.subnet_of(network) or network.subnet_of(other) or other == network:
            return True
    return False


def _dedupe(intents: list[EdgeIntent]) -> list[EdgeIntent]:
    seen: set[tuple[str, str, str]] = set()
    out: list[EdgeIntent] = []
    for intent in intents:
        key = (intent.rel_type, intent.src_native_id, intent.dst_native_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(intent)
    return out
