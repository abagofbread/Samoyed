from __future__ import annotations

from typing import Any, Protocol

from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.cloud.providers import make_scope_id, parse_scope_id
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


def find_session_for_scope(store: SessionStoreLike | None, scope_id: str) -> Any | None:
    """Find the best SessionStore match for a portable scope_id.

    Requires a strong match (scope_id / account_id / project_id metadata) so
    weak native_id substring hits do not graft unrelated sessions.
    """
    if store is None or not scope_id:
        return None
    provider, kind, identifier = parse_scope_id(scope_id)
    if not identifier:
        return None
    candidates: list[tuple[int, Any]] = []
    for session in store.list_sessions():
        score = _scope_match_score(
            session,
            scope_id=scope_id,
            provider=provider,
            kind=kind,
            identifier=identifier,
        )
        if score >= 8:
            candidates.append((score, session))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def find_session_for_account(store: SessionStoreLike | None, account_id: str) -> Any | None:
    """AWS-account convenience wrapper around find_session_for_scope."""
    if store is None or not account_id:
        return None
    return find_session_for_scope(store, make_scope_id(CloudProvider.AWS, "account", account_id))


def graft_scope_session(
    builder: GraphBuilder,
    *,
    scope_id: str,
    store: SessionStoreLike | None,
    skip_session_id: str | None = None,
) -> dict[str, Any]:
    """Copy nodes/edges from a peer-scope session into the current builder."""
    stats: dict[str, Any] = {"grafted_nodes": 0, "grafted_edges": 0, "source_session": None}
    peer = find_session_for_scope(store, scope_id)
    if peer is None:
        return stats
    if skip_session_id and getattr(peer, "session_id", None) == skip_session_id:
        return stats

    provider, kind, identifier = parse_scope_id(scope_id)
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
        props.setdefault("scope_id", scope_id)
        if kind == "account" and identifier:
            props.setdefault("account_id", identifier)
        if kind == "project" and identifier:
            props.setdefault("project_id", identifier)
        if provider is not None:
            props.setdefault("provider", provider.value)
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


def graft_account_session(
    builder: GraphBuilder,
    *,
    account_id: str,
    store: SessionStoreLike | None,
    skip_session_id: str | None = None,
) -> dict[str, Any]:
    """AWS-account convenience wrapper around graft_scope_session."""
    return graft_scope_session(
        builder,
        scope_id=make_scope_id(CloudProvider.AWS, "account", account_id),
        store=store,
        skip_session_id=skip_session_id,
    )


def ensure_scope_boundary(
    builder: GraphBuilder,
    scope_id: str,
    *,
    stub: bool = False,
    is_cross_cloud: bool = False,
) -> str:
    """Ensure a ScopeBoundary node exists for ``scope_id`` (account or project)."""
    provider, kind, identifier = parse_scope_id(scope_id)
    existing = stable_id("ScopeBoundary", scope_id)
    boundary_kind = kind or "account"
    if existing in builder.snapshot.nodes:
        node = builder.snapshot.nodes[existing]
        node.props.setdefault("boundary_kind", boundary_kind)
        node.props.setdefault("scope_id", scope_id)
        if kind == "account" and identifier:
            node.props.setdefault("account_id", identifier)
        if kind == "project" and identifier:
            node.props.setdefault("project_id", identifier)
        if stub:
            node.props["stub"] = True
        if is_cross_cloud:
            node.props["is_cross_cloud_boundary"] = True
        return existing

    if kind == "project":
        display = f"Project:{identifier}" if identifier else scope_id
        cross_account = False
    else:
        display = f"Account:{identifier}" if identifier else scope_id
        cross_account = True

    props: dict[str, Any] = {
        "display_name": display,
        "boundary_kind": boundary_kind,
        "scope_id": scope_id,
        "source": NETWORK_ENRICHMENT_SOURCE,
        "is_cross_account_boundary": cross_account,
    }
    if provider is not None:
        props["provider"] = provider.value
    if kind == "account" and identifier:
        props["account_id"] = identifier
    if kind == "project" and identifier:
        props["project_id"] = identifier
        props["is_cross_project_boundary"] = True
    if stub:
        props["stub"] = True
    if is_cross_cloud:
        props["is_cross_cloud_boundary"] = True
        props["stub"] = True

    return builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id=scope_id,
        props=props,
    )


def ensure_account_boundary(builder: GraphBuilder, account_id: str) -> str:
    """AWS-account convenience wrapper around ensure_scope_boundary."""
    return ensure_scope_boundary(
        builder,
        make_scope_id(CloudProvider.AWS, "account", account_id),
    )


def resolve_scope_or_stub(
    builder: GraphBuilder,
    *,
    scope_id: str,
    store: SessionStoreLike | None = None,
    skip_session_id: str | None = None,
    is_cross_cloud: bool = False,
) -> dict[str, Any]:
    """Graft a matching session for ``scope_id``, or emit a stub boundary if none."""
    stats = graft_scope_session(
        builder,
        scope_id=scope_id,
        store=store,
        skip_session_id=skip_session_id,
    )
    ensure_scope_boundary(
        builder,
        scope_id,
        stub=stats.get("source_session") is None,
        is_cross_cloud=is_cross_cloud,
    )
    stats["scope_id"] = scope_id
    stats["stub"] = stats.get("source_session") is None
    return stats


def peer_scope_ids(inventory: NetworkInventory, local_scope_ids: set[str]) -> set[str]:
    """Peer scope ids (accounts or projects) referenced by inventory peerings."""
    provider = (inventory.provider or "aws").lower()
    peers: set[str] = set()
    for peering in inventory.peerings:
        if not peering.is_active:
            continue
        for account in (peering.local_account_id, peering.remote_account_id):
            if not account:
                continue
            if provider == "gcp":
                scope_id = make_scope_id(CloudProvider.GCP, "project", account)
            else:
                scope_id = make_scope_id(CloudProvider.AWS, "account", account)
            if scope_id not in local_scope_ids:
                peers.add(scope_id)
    return peers


def peer_account_ids(inventory: NetworkInventory, local_account_ids: set[str]) -> set[str]:
    """AWS-oriented peer account ids (identifiers only, not full scope_ids)."""
    peers: set[str] = set()
    for peering in inventory.peerings:
        if not peering.is_active:
            continue
        for account in (peering.local_account_id, peering.remote_account_id):
            if account and account not in local_account_ids:
                peers.add(account)
    return peers


def _scope_match_score(
    session: Any,
    *,
    scope_id: str,
    provider: CloudProvider | None,
    kind: str,
    identifier: str,
) -> int:
    meta = getattr(session, "metadata", {}) or {}
    score = 0
    if getattr(session, "scope_id", "") == scope_id:
        score += 9
    if kind == "account":
        if str(meta.get("account_id") or "") == identifier:
            score += 10
        if str(meta.get("cartography_account_id") or "") == identifier:
            score += 8
    if kind == "project":
        if str(meta.get("project_id") or "") == identifier:
            score += 10
        if str(meta.get("gcp_project_id") or "") == identifier:
            score += 8
    sess_provider = getattr(session, "provider", None)
    if provider is not None and sess_provider is not None:
        prov_val = getattr(sess_provider, "value", sess_provider)
        if str(prov_val) == provider.value:
            score += 1
    snap = getattr(session, "snapshot", None)
    if snap is None:
        return score
    for node in snap.nodes.values():
        props = node.props or {}
        if str(props.get("scope_id") or "") == scope_id:
            score += 3
            break
        if kind == "account" and str(props.get("account_id") or "") == identifier:
            score += 3
            break
        if kind == "project" and str(props.get("project_id") or "") == identifier:
            score += 3
            break
        native = str(props.get("native_id") or "")
        if native == scope_id or f":{identifier}:" in native or native.endswith(f":{identifier}"):
            score += 2
            break
    return score


def _has_edge(graph: GraphSnapshot, src: str, rel: str, dst: str) -> bool:
    for dst_id, edge_rel, _props in graph.adjacency.get(src, []):
        if edge_rel == rel and dst_id == dst:
            return True
    return False
