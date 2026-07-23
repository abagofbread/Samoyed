from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder, stable_id
from samoyed.graph.enrichment import mark_enrichment_edges
from samoyed.graph.model import GraphSnapshot
from samoyed.network.model import (
    INTERNET_NATIVE_ID,
    NETWORK_ENRICHMENT_SOURCE,
    NetworkInventory,
    inventory_from_node_props,
)
from samoyed.network.reachability import EdgeIntent, evaluate_reachability
from samoyed.network.session_graft import (
    ensure_account_boundary,
    graft_account_session,
    peer_account_ids,
)


def enrich_network_reachability(
    builder: GraphBuilder,
    inventory: NetworkInventory | None = None,
    *,
    session_store: Any | None = None,
    inventory_source: str = "",
) -> dict[str, int]:
    """Apply SG-lite network edges onto the graph from a NetworkInventory."""
    graph = builder.snapshot
    derived = inventory_from_node_props(graph.nodes.values())
    merged = (inventory or NetworkInventory()).merge(derived)
    if inventory_source and not merged.source:
        merged.source = inventory_source

    stats = {
        "placements": len(merged.placements),
        "peerings": len(merged.peerings),
        "sg_rules": len(merged.sg_rules),
        "network_edges": 0,
        "grafted_nodes": 0,
        "grafted_edges": 0,
        "account_boundaries": 0,
    }
    if merged.is_empty():
        return stats

    _apply_placement_props(builder, merged)
    _ensure_internet_node(builder)

    local_accounts = {p.account_id for p in merged.placements if p.account_id}
    for account_id in peer_account_ids(merged, local_accounts):
        ensure_account_boundary(builder, account_id)
        stats["account_boundaries"] += 1
        graft = graft_account_session(
            builder,
            account_id=account_id,
            store=session_store,
            skip_session_id=builder.session_id,
        )
        stats["grafted_nodes"] += int(graft.get("grafted_nodes") or 0)
        stats["grafted_edges"] += int(graft.get("grafted_edges") or 0)

    # Re-merge placements from grafted nodes so peering CAN_REACH can resolve remote compute.
    merged = merged.merge(inventory_from_node_props(builder.snapshot.nodes.values()))

    intents = evaluate_reachability(merged)
    native_to_id = _native_id_index(builder.snapshot)
    for intent in intents:
        if intent.rel_type == "VPC_PEERS" and intent.dst_native_id.startswith("aws:account:"):
            account_id = intent.dst_native_id.split(":")[-1]
            dst_id = ensure_account_boundary(builder, account_id)
            native_to_id[intent.dst_native_id] = dst_id
            native_to_id[f"aws:account:{account_id}"] = dst_id
        src_id = _resolve_native(builder, native_to_id, intent.src_native_id, intent)
        dst_id = _resolve_native(builder, native_to_id, intent.dst_native_id, intent)
        if not src_id or not dst_id:
            continue
        if _has_edge(builder.snapshot, src_id, intent.rel_type, dst_id):
            continue
        props = {
            "source": NETWORK_ENRICHMENT_SOURCE,
            "mechanism": intent.mechanism,
            "confidence": "explicit",
            "inventory_source": merged.source or inventory_source,
            **intent.props,
        }
        if intent.rel_type == "BRIDGES_TO":
            props["ui_label"] = ""
            props["boundary_crossing"] = True
        builder.add_edge(src_id=src_id, rel_type=intent.rel_type, dst_id=dst_id, props=props)
        stats["network_edges"] += 1

    stats["enrichment_edges_marked"] = mark_enrichment_edges(builder.snapshot)
    return stats


def _ensure_internet_node(builder: GraphBuilder) -> str:
    existing = stable_id("Resource", INTERNET_NATIVE_ID)
    if existing in builder.snapshot.nodes:
        node = builder.snapshot.nodes[existing]
        node.props["display_name"] = "The Internet"
        node.props.setdefault("exposure_level", "internet")
        node.props.setdefault("resource_type", "NetworkExposure")
        return existing
    return builder.add_concept_node(
        concept_type=ConceptType.NETWORK_EXPOSURE,
        native_id=INTERNET_NATIVE_ID,
        props={
            "display_name": "The Internet",
            "exposure_level": "internet",
            "resource_type": "NetworkExposure",
            "source": NETWORK_ENRICHMENT_SOURCE,
        },
    )


def _apply_placement_props(builder: GraphBuilder, inventory: NetworkInventory) -> None:
    by_native = {p.native_id: p for p in inventory.placements}
    for node in builder.snapshot.nodes.values():
        native = node.props.get("native_id")
        placement = by_native.get(str(native)) if native else None
        if placement is None:
            continue
        if placement.vpc_id:
            node.props["vpc_id"] = placement.vpc_id
        if placement.sg_ids:
            node.props["sg_ids"] = list(placement.sg_ids)
        if placement.subnet_ids:
            node.props["subnet_ids"] = list(placement.subnet_ids)
        if placement.private_ips:
            node.props["private_ips"] = list(placement.private_ips)
        if placement.public_ip:
            node.props["public_ip"] = placement.public_ip
        if placement.account_id:
            node.props.setdefault("account_id", placement.account_id)
        if placement.exposed_internet:
            node.props["exposed_internet"] = True


def _native_id_index(graph: GraphSnapshot) -> dict[str, str]:
    index: dict[str, str] = {}
    for node_id, node in graph.nodes.items():
        concept = node.props.get("concept_type")
        # EscapeSurface/IMDS nodes copy instance_id from compute — do not let them
        # steal EC2Instance:* resolution used for network edges.
        if concept in {"EscapeSurface", "NetworkExposure"}:
            native = node.props.get("native_id")
            if native:
                index.setdefault(str(native), node_id)
            continue
        native = node.props.get("native_id")
        if native:
            index[str(native)] = node_id
        arn = node.props.get("arn")
        if arn:
            index[str(arn)] = node_id
        instance_id = node.props.get("instance_id")
        if instance_id and concept in {"RuntimeBinding", "Workload", None}:
            # Prefer explicit RuntimeBinding native_id mapping; only fill alias if free.
            index.setdefault(f"EC2Instance:{instance_id}", node_id)
    return index


def _resolve_native(
    builder: GraphBuilder,
    index: dict[str, str],
    native_id: str,
    intent: EdgeIntent,
) -> str | None:
    if native_id == INTERNET_NATIVE_ID or native_id == "network:internet":
        return _ensure_internet_node(builder)
    if native_id in index:
        return index[native_id]
    if native_id.startswith("aws:account:"):
        account_id = native_id.split(":")[-1]
        node_id = ensure_account_boundary(builder, account_id)
        index[native_id] = node_id
        return node_id
    # Create stub RuntimeBinding for inventory-only compute (e.g. remote account in same tfstate).
    if intent.rel_type in {"CAN_REACH", "BRIDGES_TO", "VPC_PEERS"} and (
        native_id.startswith("EC2Instance:")
        or native_id.startswith("LambdaFunction:")
        or native_id.startswith("ECSTask:")
    ):
        rtype = native_id.split(":", 1)[0]
        node_id = builder.add_concept_node(
            concept_type=ConceptType.RUNTIME_BINDING,
            native_id=native_id,
            props={
                "display_name": native_id,
                "resource_type": rtype,
                "source": NETWORK_ENRICHMENT_SOURCE,
                "stub_from_network": True,
            },
        )
        index[native_id] = node_id
        return node_id
    return None


def _has_edge(graph: GraphSnapshot, src: str, rel: str, dst: str) -> bool:
    for dst_id, edge_rel, _props in graph.adjacency.get(src, []):
        if edge_rel == rel and dst_id == dst:
            return True
    return False
