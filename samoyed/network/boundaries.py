"""Synthesize NetworkBoundary nodes (VPC/subnet) and HOSTED_IN placement edges."""

from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.cloud.providers import make_scope_id
from samoyed.graph.builder import GraphBuilder, stable_id
from samoyed.graph.model import GraphSnapshot
from samoyed.network.model import NETWORK_ENRICHMENT_SOURCE, NetworkInventory
from samoyed.network.session_graft import ensure_account_boundary


def synthesize_network_boundaries(
    builder: GraphBuilder,
    inventory: NetworkInventory,
) -> dict[str, int]:
    """Create VPC/subnet NetworkBoundary nodes and wire HOSTED_IN placement edges.

    Hierarchy emitted (when data is present)::

        compute -HOSTED_IN-> subnet -HOSTED_IN-> vpc -HOSTED_IN-> account

    If a placement has a VPC but no subnet, compute hosts directly in the VPC.
    Account ScopeBoundary nodes are tagged with ``boundary_kind=account``.
    Idempotent: existing native_ids are reused; duplicate HOSTED_IN edges are skipped.
    """
    stats = {
        "vpc_boundaries": 0,
        "subnet_boundaries": 0,
        "account_boundaries_tagged": 0,
        "hosted_in_edges": 0,
    }
    if inventory.is_empty():
        return stats

    vpc_accounts: dict[str, str] = {}
    subnet_vpcs: dict[str, str] = {}
    for placement in inventory.placements:
        if placement.vpc_id:
            if placement.account_id:
                vpc_accounts.setdefault(placement.vpc_id, placement.account_id)
            for subnet_id in placement.subnet_ids:
                subnet_vpcs.setdefault(subnet_id, placement.vpc_id)

    provider = (inventory.provider or "aws").lower()
    provider_enum = CloudProvider.GCP if provider == "gcp" else CloudProvider.AWS
    vpc_prefix = "gcp:vpc" if provider == "gcp" else "aws:vpc"
    subnet_prefix = "gcp:subnet" if provider == "gcp" else "aws:subnet"

    vpc_node_ids: dict[str, str] = {}
    for vpc_id, account_id in sorted(vpc_accounts.items()):
        native_id = f"{vpc_prefix}:{vpc_id}"
        existed = stable_id("NetworkBoundary", native_id) in builder.snapshot.nodes
        node_id = _ensure_vpc_boundary(
            builder,
            vpc_id=vpc_id,
            account_id=account_id,
            cidrs=list(inventory.vpc_cidrs.get(vpc_id) or []),
            provider=provider_enum,
            native_id=native_id,
        )
        vpc_node_ids[vpc_id] = node_id
        if not existed:
            stats["vpc_boundaries"] += 1

        if account_id:
            if provider == "gcp":
                from samoyed.network.session_graft import ensure_scope_boundary

                account_node = ensure_scope_boundary(
                    builder, make_scope_id(CloudProvider.GCP, "project", account_id)
                )
                if _tag_scope_boundary(
                    builder.snapshot, account_node, account_id, kind="project", provider=provider_enum
                ):
                    stats["account_boundaries_tagged"] += 1
            else:
                account_node = ensure_account_boundary(builder, account_id)
                if _tag_account_boundary(builder.snapshot, account_node, account_id):
                    stats["account_boundaries_tagged"] += 1
            if _add_hosted_in(builder, node_id, account_node):
                stats["hosted_in_edges"] += 1

    # Also tag any other account/project ScopeBoundary already present (session root).
    for node_id, node in list(builder.snapshot.nodes.items()):
        if node.label != "ScopeBoundary":
            continue
        native = str(node.props.get("native_id") or "")
        account_id = str(node.props.get("account_id") or node.props.get("project_id") or "")
        if native.startswith("aws:account:") or native.startswith("gcp:project:") or account_id:
            if not account_id and ":" in native:
                account_id = native.rsplit(":", 1)[-1]
            if native.startswith("gcp:project:"):
                if _tag_scope_boundary(
                    builder.snapshot, node_id, account_id, kind="project", provider=CloudProvider.GCP
                ):
                    stats["account_boundaries_tagged"] += 1
            elif _tag_account_boundary(builder.snapshot, node_id, account_id):
                stats["account_boundaries_tagged"] += 1

    subnet_node_ids: dict[str, str] = {}
    for subnet_id, vpc_id in sorted(subnet_vpcs.items()):
        vpc_node = vpc_node_ids.get(vpc_id)
        if not vpc_node:
            continue
        account_id = vpc_accounts.get(vpc_id, "")
        native_id = f"{subnet_prefix}:{subnet_id}"
        existed = stable_id("NetworkBoundary", native_id) in builder.snapshot.nodes
        node_id = _ensure_subnet_boundary(
            builder,
            subnet_id=subnet_id,
            vpc_id=vpc_id,
            account_id=account_id,
            provider=provider_enum,
            native_id=native_id,
        )
        subnet_node_ids[subnet_id] = node_id
        if not existed:
            stats["subnet_boundaries"] += 1
        if _add_hosted_in(builder, node_id, vpc_node):
            stats["hosted_in_edges"] += 1

    native_index = _native_id_index(builder.snapshot)
    for placement in inventory.placements:
        node_id = native_index.get(placement.native_id)
        if not node_id:
            continue
        host_id: str | None = None
        if placement.subnet_ids:
            # Prefer the first subnet that we synthesized.
            for subnet_id in placement.subnet_ids:
                host_id = subnet_node_ids.get(subnet_id)
                if host_id:
                    break
        if not host_id and placement.vpc_id:
            host_id = vpc_node_ids.get(placement.vpc_id)
        if not host_id:
            continue
        if _add_hosted_in(
            builder,
            node_id,
            host_id,
            extra={"placement": True},
        ):
            stats["hosted_in_edges"] += 1

    return stats


def _ensure_vpc_boundary(
    builder: GraphBuilder,
    *,
    vpc_id: str,
    account_id: str,
    cidrs: list[str],
    provider: CloudProvider = CloudProvider.AWS,
    native_id: str | None = None,
) -> str:
    native_id = native_id or f"aws:vpc:{vpc_id}"
    existing = stable_id("NetworkBoundary", native_id)
    if existing in builder.snapshot.nodes:
        node = builder.snapshot.nodes[existing]
        node.props.setdefault("boundary_kind", "vpc")
        if account_id:
            key = "project_id" if provider == CloudProvider.GCP else "account_id"
            node.props.setdefault(key, account_id)
            node.props.setdefault("account_id", account_id)
        if cidrs:
            node.props["cidrs"] = list(cidrs)
        node.props.setdefault("display_name", f"VPC {vpc_id}")
        return existing
    props: dict[str, Any] = {
        "display_name": f"VPC {vpc_id}",
        "boundary_kind": "vpc",
        "vpc_id": vpc_id,
        "account_id": account_id,
        "cidrs": list(cidrs),
        "provider": provider.value,
        "source": NETWORK_ENRICHMENT_SOURCE,
    }
    if provider == CloudProvider.GCP and account_id:
        props["project_id"] = account_id
    return builder.add_concept_node(
        concept_type=ConceptType.NETWORK_BOUNDARY,
        native_id=native_id,
        props=props,
    )


def _ensure_subnet_boundary(
    builder: GraphBuilder,
    *,
    subnet_id: str,
    vpc_id: str,
    account_id: str,
    provider: CloudProvider = CloudProvider.AWS,
    native_id: str | None = None,
) -> str:
    native_id = native_id or f"aws:subnet:{subnet_id}"
    existing = stable_id("NetworkBoundary", native_id)
    if existing in builder.snapshot.nodes:
        node = builder.snapshot.nodes[existing]
        node.props.setdefault("boundary_kind", "subnet")
        node.props.setdefault("vpc_id", vpc_id)
        if account_id:
            node.props.setdefault("account_id", account_id)
            if provider == CloudProvider.GCP:
                node.props.setdefault("project_id", account_id)
        node.props.setdefault("display_name", f"Subnet {subnet_id}")
        return existing
    props = {
        "display_name": f"Subnet {subnet_id}",
        "boundary_kind": "subnet",
        "subnet_id": subnet_id,
        "vpc_id": vpc_id,
        "account_id": account_id,
        "provider": provider.value,
        "source": NETWORK_ENRICHMENT_SOURCE,
    }
    if provider == CloudProvider.GCP and account_id:
        props["project_id"] = account_id
    return builder.add_concept_node(
        concept_type=ConceptType.NETWORK_BOUNDARY,
        native_id=native_id,
        props=props,
    )


def _tag_account_boundary(graph: GraphSnapshot, node_id: str, account_id: str) -> bool:
    return _tag_scope_boundary(
        graph, node_id, account_id, kind="account", provider=CloudProvider.AWS
    )


def _tag_scope_boundary(
    graph: GraphSnapshot,
    node_id: str,
    identifier: str,
    *,
    kind: str,
    provider: CloudProvider,
) -> bool:
    node = graph.nodes.get(node_id)
    if node is None:
        return False
    changed = False
    if node.props.get("boundary_kind") != kind:
        node.props["boundary_kind"] = kind
        changed = True
    id_key = "project_id" if kind == "project" else "account_id"
    if identifier and not node.props.get(id_key):
        node.props[id_key] = identifier
        changed = True
    if identifier and kind == "project":
        node.props.setdefault("account_id", identifier)
    if identifier and not node.props.get("native_id"):
        node.props["native_id"] = make_scope_id(provider, kind, identifier)
        changed = True
    return changed


def _add_hosted_in(
    builder: GraphBuilder,
    src_id: str,
    dst_id: str,
    *,
    extra: dict[str, Any] | None = None,
) -> bool:
    if not src_id or not dst_id or src_id == dst_id:
        return False
    if _has_edge(builder.snapshot, src_id, "HOSTED_IN", dst_id):
        return False
    props: dict[str, Any] = {
        "source": NETWORK_ENRICHMENT_SOURCE,
        "confidence": "explicit",
    }
    if extra:
        props.update(extra)
    builder.add_edge(src_id=src_id, rel_type="HOSTED_IN", dst_id=dst_id, props=props)
    return True


def _has_edge(graph: GraphSnapshot, src: str, rel: str, dst: str) -> bool:
    for dst_id, edge_rel, _props in graph.adjacency.get(src, []):
        if edge_rel == rel and dst_id == dst:
            return True
    return False


def _native_id_index(graph: GraphSnapshot) -> dict[str, str]:
    index: dict[str, str] = {}
    for node_id, node in graph.nodes.items():
        concept = node.props.get("concept_type")
        if concept in {"NetworkExposure", "NetworkBoundary", "ScopeBoundary", "OrchestrationScope"}:
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
            index.setdefault(f"EC2Instance:{instance_id}", node_id)
    return index

