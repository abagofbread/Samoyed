from __future__ import annotations

from typing import Any, Protocol

from samoyed.cloud.concepts import ConceptType
from samoyed.cloud.providers import make_scope_id
from samoyed.cloud.concepts import CloudProvider
from samoyed.graph.builder import GraphBuilder, stable_id
from samoyed.graph.model import GraphNode, GraphSnapshot
from samoyed.network.model import NETWORK_ENRICHMENT_SOURCE, NetworkInventory


class SessionLike(Protocol):
    session_id: str
    snapshot: GraphSnapshot
    metadata: dict[str, Any]
    scope_id: str


class SessionStoreLike(Protocol):
    def list_sessions(self) -> list[Any]: ...

    def get(self, session_id: str) -> Any | None: ...


def find_session_for_account(store: SessionStoreLike | None, account_id: str) -> Any | None:
    if store is None or not account_id:
        return None
    scope_id = make_scope_id(CloudProvider.AWS, "account", account_id)
    candidates: list[tuple[int, Any]] = []
    for session in store.list_sessions():
        score = _account_match_score(session, account_id=account_id, scope_id=scope_id)
        if score > 0:
            candidates.append((score, session))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def graft_account_session(
    builder: GraphBuilder,
    *,
    account_id: str,
    store: SessionStoreLike | None,
    skip_session_id: str | None = None,
) -> dict[str, Any]:
    """Copy nodes/edges from a peer-account session into the current builder."""
    stats = {"grafted_nodes": 0, "grafted_edges": 0, "source_session": None}
    peer = find_session_for_account(store, account_id)
    if peer is None:
        return stats
    if skip_session_id and getattr(peer, "session_id", None) == skip_session_id:
        return stats

    stats["source_session"] = peer.session_id
    snap: GraphSnapshot = peer.snapshot
    existing = set(builder.snapshot.nodes.keys())

    for node_id, node in snap.nodes.items():
        if node.label == "CollectionSession":
            continue
        if node_id in existing:
            continue
        props = dict(node.props)
        props["grafted_from_session"] = peer.session_id
        props.setdefault("account_id", account_id)
        builder.snapshot.add_node(GraphNode(node_id=node_id, label=node.label, props=props))
        stats["grafted_nodes"] += 1
        existing.add(node_id)

    for edge in snap.edges:
        if edge.rel_type == "DISCOVERED":
            continue
        if edge.src_id not in builder.snapshot.nodes or edge.dst_id not in builder.snapshot.nodes:
            continue
        if _has_edge(builder.snapshot, edge.src_id, edge.rel_type, edge.dst_id):
            continue
        props = dict(edge.props)
        props["grafted_from_session"] = peer.session_id
        builder.add_edge(
            src_id=edge.src_id,
            rel_type=edge.rel_type,
            dst_id=edge.dst_id,
            props=props,
        )
        stats["grafted_edges"] += 1
    return stats


def ensure_account_boundary(builder: GraphBuilder, account_id: str) -> str:
    scope_id = make_scope_id(CloudProvider.AWS, "account", account_id)
    existing = stable_id("ScopeBoundary", scope_id)
    if existing in builder.snapshot.nodes:
        node = builder.snapshot.nodes[existing]
        node.props.setdefault("boundary_kind", "account")
        node.props.setdefault("account_id", account_id)
        return existing
    return builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id=scope_id,
        props={
            "display_name": f"Account:{account_id}",
            "account_id": account_id,
            "boundary_kind": "account",
            "source": NETWORK_ENRICHMENT_SOURCE,
            "is_cross_account_boundary": True,
        },
    )


def peer_account_ids(inventory: NetworkInventory, local_account_ids: set[str]) -> set[str]:
    peers: set[str] = set()
    for peering in inventory.peerings:
        if not peering.is_active:
            continue
        for account in (peering.local_account_id, peering.remote_account_id):
            if account and account not in local_account_ids:
                peers.add(account)
    return peers


def _account_match_score(session: Any, *, account_id: str, scope_id: str) -> int:
    meta = getattr(session, "metadata", {}) or {}
    score = 0
    if str(meta.get("account_id") or "") == account_id:
        score += 10
    if str(meta.get("cartography_account_id") or "") == account_id:
        score += 8
    if getattr(session, "scope_id", "") == scope_id:
        score += 9
    snap = getattr(session, "snapshot", None)
    if snap is None:
        return score
    for node in snap.nodes.values():
        props = node.props or {}
        if str(props.get("account_id") or "") == account_id:
            score += 3
            break
        native = str(props.get("native_id") or "")
        if native == scope_id or f":{account_id}:" in native or native.endswith(f":{account_id}"):
            score += 2
            break
    return score


def _has_edge(graph: GraphSnapshot, src: str, rel: str, dst: str) -> bool:
    for dst_id, edge_rel, _props in graph.adjacency.get(src, []):
        if edge_rel == rel and dst_id == dst:
            return True
    return False
