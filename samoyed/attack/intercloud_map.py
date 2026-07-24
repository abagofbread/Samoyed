"""Describe cross-cloud bridges and top attack paths across sessions."""

from __future__ import annotations

from typing import Any

from samoyed.attack.cross_cloud_resolve import enrich_cross_cloud_resolve
from samoyed.cloud.concepts import CloudProvider
from samoyed.cloud.providers import normalize_scope_id, parse_scope_id
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import find_compromised_nodes
from samoyed.network.session_graft import find_session_for_scope, graft_scope_session
from samoyed.path_engine.search import find_attack_paths, get_blast_radius

_BRIDGE_RELS = frozenset({"CAN_ASSUME_ROLE", "PROJECTS_TO", "VPC_PEERS", "BRIDGES_TO"})
_BRIDGE_MECHANISMS = frozenset(
    {"wif", "oidc-federation", "synced-identity", "cross-cloud", "add-secret"}
)


def describe_intercloud_paths(
    session_store: Any,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Map ScopeBoundaries, federation bridges, graft peers, and top cross-cloud paths."""
    sessions = list(session_store.list_sessions())
    session_summaries = [
        {
            "session_id": getattr(s, "session_id", None),
            "provider": _provider_value(getattr(s, "provider", None)),
            "scope_id": normalize_scope_id(str(getattr(s, "scope_id", "") or "")),
            "caller_arn": getattr(s, "caller_arn", None),
            "node_count": len(getattr(getattr(s, "snapshot", None), "nodes", {}) or {}),
        }
        for s in sessions
    ]

    session = None
    if session_id:
        session = session_store.get(session_id) if hasattr(session_store, "get") else None
        if session is None and hasattr(session_store, "resolve_session_ref"):
            session = session_store.resolve_session_ref(session_id)
    elif hasattr(session_store, "resolve_session_ref"):
        session = session_store.resolve_session_ref(None)
    elif sessions:
        session = sessions[0]

    if session is None:
        return {
            "error": "session not found",
            "sessions": session_summaries,
            "components": [],
            "bridges": [],
            "top_paths": [],
        }

    builder = GraphBuilder(session.session_id)
    builder.snapshot = session.snapshot
    local_provider = getattr(session, "provider", None)
    if isinstance(local_provider, str):
        try:
            local_provider = CloudProvider(local_provider)
        except ValueError:
            local_provider = None

    graft_stats = enrich_cross_cloud_resolve(
        builder,
        session_store=session_store,
        local_provider=local_provider,
    )
    # Explicit peer grafts for every foreign ScopeBoundary already present.
    for node in list(builder.snapshot.nodes.values()):
        if node.label != "ScopeBoundary":
            continue
        scope = normalize_scope_id(str(node.props.get("native_id") or ""))
        if not scope or scope == normalize_scope_id(str(getattr(session, "scope_id", "") or "")):
            continue
        peer = find_session_for_scope(session_store, scope)
        if peer is None or peer.session_id == session.session_id:
            continue
        graft_scope_session(
            builder,
            scope_id=scope,
            store=session_store,
            skip_session_id=session.session_id,
        )

    bridges = _collect_bridges(builder.snapshot)
    components = _provider_components(builder.snapshot, bridges)
    start = _resolve_start(session_store, session)
    top_paths: list[dict[str, Any]] = []
    if start:
        paths = find_attack_paths(
            builder.snapshot,
            start_node_id=start,
            target_concept="high_value",
            max_depth=8,
            max_paths=15,
        )
        if not paths:
            paths = find_attack_paths(
                builder.snapshot,
                start_node_id=start,
                target_concept="SecretStore",
                max_depth=8,
                max_paths=15,
            )
        if not paths:
            paths = get_blast_radius(builder.snapshot, start_node_id=start, max_depth=8, max_paths=15)
        crossing = [p for p in paths if _path_provider_count(builder.snapshot, p) >= 2]
        chosen = crossing or paths
        for path in chosen[:8]:
            top_paths.append(
                {
                    "path_id": path.path_id,
                    "score": path.score,
                    "node_ids": path.node_ids,
                    "providers": sorted(_path_providers(builder.snapshot, path)),
                    "steps": [
                        {
                            "step": s.step_index,
                            "src": s.src_id,
                            "rel": s.rel_type,
                            "dst": s.dst_id,
                            "mechanism": (s.evidence or {}).get("mechanism"),
                        }
                        for s in path.steps
                    ],
                    "target_match": path.target_match,
                }
            )

    try:
        if hasattr(session_store, "_persist"):
            session_store._persist(session)
    except Exception:
        pass

    return {
        "session_id": session.session_id,
        "scope_id": normalize_scope_id(str(getattr(session, "scope_id", "") or "")),
        "provider": _provider_value(local_provider),
        "sessions": session_summaries,
        "graft": graft_stats,
        "components": components,
        "bridges": bridges,
        "top_paths": top_paths,
        "start_node_id": start,
    }


def _resolve_start(session_store: Any, session: Any) -> str | None:
    if hasattr(session_store, "resolve_start_node"):
        for alias in ("compromised", "caller", "host"):
            try:
                start = session_store.resolve_start_node(session.session_id, alias)
            except Exception:
                start = None
            if start:
                return start
    compromised = find_compromised_nodes(session.snapshot)
    if compromised:
        return compromised[0]
    if hasattr(session_store, "find_caller_node"):
        return session_store.find_caller_node(session)
    for node in session.snapshot.nodes.values():
        if node.props.get("is_caller") or node.props.get("is_scenario_start"):
            return node.node_id
    return None


def _collect_bridges(snapshot: Any) -> list[dict[str, Any]]:
    bridges: list[dict[str, Any]] = []
    for edge in snapshot.edges:
        if edge.rel_type not in _BRIDGE_RELS:
            continue
        mechanism = str((edge.props or {}).get("mechanism") or "")
        src = snapshot.nodes.get(edge.src_id)
        dst = snapshot.nodes.get(edge.dst_id)
        if src is None or dst is None:
            continue
        src_provider = _infer_provider(src.props)
        dst_provider = _infer_provider(dst.props)
        is_foreign = bool(src_provider and dst_provider and src_provider != dst_provider)
        is_boundary = src.label == "ScopeBoundary" or dst.label == "ScopeBoundary"
        if not (mechanism in _BRIDGE_MECHANISMS or is_foreign or is_boundary):
            continue
        bridges.append(
            {
                "src": edge.src_id,
                "dst": edge.dst_id,
                "rel": edge.rel_type,
                "mechanism": mechanism or None,
                "src_provider": src_provider,
                "dst_provider": dst_provider,
                "src_native_id": src.props.get("native_id"),
                "dst_native_id": dst.props.get("native_id"),
                "boundary_crossing": bool((edge.props or {}).get("boundary_crossing"))
                or is_foreign
                or is_boundary,
            }
        )
    return bridges


def _provider_components(snapshot: Any, bridges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scopes: set[str] = set()
    for node in snapshot.nodes.values():
        if node.label == "ScopeBoundary" and node.props.get("native_id"):
            scopes.add(normalize_scope_id(str(node.props["native_id"])))
        sid = normalize_scope_id(str(node.props.get("scope_id") or ""))
        if sid:
            scopes.add(sid)

    parent = {s: s for s in scopes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for bridge in bridges:
        src_scope = _scope_for_node(snapshot, bridge["src"])
        dst_scope = _scope_for_node(snapshot, bridge["dst"])
        if src_scope and dst_scope and src_scope in parent and dst_scope in parent:
            union(src_scope, dst_scope)
        elif src_scope and src_scope in parent and bridge.get("dst_provider"):
            # Keep single-scope component annotated with foreign provider hint
            pass

    grouped: dict[str, set[str]] = {}
    for scope in scopes:
        grouped.setdefault(find(scope), set()).add(scope)

    components: list[dict[str, Any]] = []
    for root, members in grouped.items():
        providers: set[str] = set()
        for scope in members:
            provider, _kind, _ident = parse_scope_id(scope)
            if provider:
                providers.add(provider.value)
        components.append(
            {
                "id": root,
                "scope_ids": sorted(members),
                "providers": sorted(providers),
                "bridge_count": sum(
                    1
                    for b in bridges
                    if (_scope_for_node(snapshot, b["src"]) in members)
                    or (_scope_for_node(snapshot, b["dst"]) in members)
                ),
            }
        )
    components.sort(key=lambda c: (-len(c["providers"]), -len(c["scope_ids"])))
    return components


def _scope_for_node(snapshot: Any, node_id: str) -> str | None:
    node = snapshot.nodes.get(node_id)
    if not node:
        return None
    if node.label == "ScopeBoundary" and node.props.get("native_id"):
        return normalize_scope_id(str(node.props["native_id"]))
    sid = normalize_scope_id(str(node.props.get("scope_id") or ""))
    if sid:
        return sid
    provider = _infer_provider(node.props)
    if provider == "aws":
        account = str(node.props.get("account_id") or "")
        if account:
            return f"aws:account:{account}"
    if provider == "gcp":
        project = str(node.props.get("project_id") or "")
        if project:
            return f"gcp:project:{project}"
    if provider == "azure":
        sub = str(node.props.get("subscription_id") or "")
        if sub:
            return f"azure:subscription:{sub}"
    return None


def _infer_provider(props: dict[str, Any]) -> str | None:
    provider = str(props.get("provider") or props.get("provider_hint") or "")
    if provider in {"aws", "gcp", "azure", "kubernetes"}:
        return provider
    native = str(props.get("native_id") or "")
    if native.startswith("arn:aws") or native.startswith("aws:"):
        return "aws"
    if native.startswith(("gcp:", "GCSBucket:", "GCPSecret:", "CloudRun", "CloudFunction", "GCEInstance:")):
        return "gcp"
    if native.startswith(
        (
            "azure:",
            "StorageAccount:",
            "KeyVault:",
            "KeyVaultSecret:",
            "AzureVM:",
            "WebApp:",
            "FunctionApp:",
            "AutomationAccount:",
            "AcrRegistry:",
        )
    ):
        return "azure"
    return None


def _path_providers(snapshot: Any, path: Any) -> set[str]:
    providers: set[str] = set()
    for node_id in path.node_ids:
        node = snapshot.nodes.get(node_id)
        if not node:
            continue
        provider = _infer_provider(node.props)
        if provider in {"aws", "gcp", "azure"}:
            providers.add(provider)
    return providers


def _path_provider_count(snapshot: Any, path: Any) -> int:
    return len(_path_providers(snapshot, path))


def _provider_value(provider: Any) -> str | None:
    if provider is None:
        return None
    return getattr(provider, "value", str(provider))
