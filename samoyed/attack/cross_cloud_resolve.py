"""When pivots land in a foreign cloud/scope, graft peer sessions or stub boundaries."""

from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import CloudProvider
from samoyed.cloud.providers import make_scope_id, parse_scope_id
from samoyed.graph.builder import GraphBuilder
from samoyed.network.session_graft import resolve_scope_or_stub


def enrich_cross_cloud_resolve(
    builder: GraphBuilder,
    *,
    session_store: Any | None = None,
    local_provider: CloudProvider | None = None,
) -> dict[str, int]:
    """Scan pivot edges for foreign scopes and graft/stub them."""
    stats = {"cross_cloud_resolved": 0, "cross_cloud_stubs": 0, "cross_cloud_grafted": 0}
    if session_store is None and not builder.snapshot.nodes:
        return stats

    local_scope = ""
    for node in builder.snapshot.nodes.values():
        if node.label == "ScopeBoundary" and node.props.get("native_id"):
            local_scope = str(node.props["native_id"])
            break

    seen: set[str] = set()
    for edge in list(builder.snapshot.edges):
        if edge.rel_type not in {"CAN_ASSUME_ROLE", "PROJECTS_TO", "BRIDGES_TO", "VPC_PEERS"}:
            continue
        dst = builder.snapshot.nodes.get(edge.dst_id)
        if dst is None:
            continue
        scope_id = _foreign_scope(dst.props, local_provider=local_provider, local_scope=local_scope)
        if not scope_id or scope_id in seen:
            continue
        if local_scope and scope_id == local_scope:
            continue
        seen.add(scope_id)
        provider, _kind, _ident = parse_scope_id(scope_id)
        is_cross_cloud = bool(
            local_provider is not None and provider is not None and provider != local_provider
        )
        result = resolve_scope_or_stub(
            builder,
            scope_id=scope_id,
            store=session_store,
            skip_session_id=builder.session_id,
            is_cross_cloud=is_cross_cloud or bool(edge.props.get("mechanism") in {"wif", "oidc-federation"}),
        )
        stats["cross_cloud_resolved"] += 1
        if result.get("stub"):
            stats["cross_cloud_stubs"] += 1
        else:
            stats["cross_cloud_grafted"] += 1
            # Wire a soft BRIDGES_TO from the pivot destination into the scope boundary
            # when not already connected.
            boundary_native = scope_id
            for node_id, node in builder.snapshot.nodes.items():
                if node.props.get("native_id") == boundary_native:
                    if not _has_edge(builder, edge.dst_id, "BRIDGES_TO", node_id):
                        builder.add_edge(
                            src_id=edge.dst_id,
                            rel_type="BRIDGES_TO",
                            dst_id=node_id,
                            props={
                                "source": "cross-cloud-resolve",
                                "mechanism": edge.props.get("mechanism") or "cross-cloud",
                                "ui_label": "",
                                "boundary_crossing": True,
                            },
                        )
                    break
    return stats


def _foreign_scope(
    props: dict[str, Any],
    *,
    local_provider: CloudProvider | None,
    local_scope: str,
) -> str | None:
    native = str(props.get("native_id") or "")
    provider_hint = str(props.get("provider") or props.get("provider_hint") or "")
    project_id = str(props.get("project_id") or "")
    account_id = str(props.get("account_id") or "")

    if native.startswith("gcp:") or provider_hint == "gcp" or native.startswith("GCSBucket:") or native.startswith("GCPSecret:"):
        if project_id:
            return make_scope_id(CloudProvider.GCP, "project", project_id)
        if native.startswith("gcp:serviceaccount:") and "@" in native:
            # email project suffix: name@project.iam.gserviceaccount.com
            email = native.split(":", 1)[1]
            if ".iam.gserviceaccount.com" in email:
                proj = email.split("@", 1)[1].split(".iam.gserviceaccount.com", 1)[0]
                if proj:
                    return make_scope_id(CloudProvider.GCP, "project", proj)
        if local_provider != CloudProvider.GCP and local_scope.startswith("gcp:"):
            return local_scope
        return None

    if native.startswith("arn:aws:") or provider_hint == "aws":
        if account_id:
            return make_scope_id(CloudProvider.AWS, "account", account_id)
        parts = native.split(":")
        if len(parts) > 4 and parts[4].isdigit():
            return make_scope_id(CloudProvider.AWS, "account", parts[4])
        return None

    scope_prop = str(props.get("scope_id") or "")
    if scope_prop and scope_prop != local_scope:
        return scope_prop
    return None


def _has_edge(builder: GraphBuilder, src: str, rel: str, dst: str) -> bool:
    for dst_id, edge_rel, _props in builder.snapshot.adjacency.get(src, []):
        if edge_rel == rel and dst_id == dst:
            return True
    return False
