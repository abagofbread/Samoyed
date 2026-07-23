"""Resource-mediated pivots: principal capability ∩ consumer use → FEEDS.

When a principal can WRITES/CONTROLS a resource scope and a workload/identity
READS / USES_IMAGE / PULLS_FROM / DEPENDS_ON an intersecting scope, emit:

  principal --FEEDS--> consumer

with scope_intersection props so paths continue past type-level resource nodes.
"""

from __future__ import annotations

from typing import Any

from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.resource_scope import (
    CONSUMER_RELS,
    PRODUCER_RELS,
    ResourceScope,
    ScopeIntersection,
    intersect_scopes,
    scopes_from_edge_props,
)

# Only resource families where write→consume is a meaningful poison pivot.
# IAM service wildcards (Logs:*, Ec2:*, …) live in family "other" and must not FEEDS.
FEEDS_FAMILIES = frozenset({"s3", "secretsmanager", "ecr", "ssm", "rds"})

# IAM Identity READS of a resource are authorization shape, not "uses this for work".
# FEEDS only to use-side consumers — otherwise every shared Secret:*/S3:* becomes a
# principal↔principal enrichment mesh (e.g. AWSServiceRoleForAPIGateway × all roles).
_USE_CONSUMER_CONCEPTS = frozenset(
    {
        "Workload",
        "RuntimeBinding",
        "ImageProvenance",
        "RegistryStore",
        "EscapeSurface",
    }
)
_USE_CONSUMER_RELS = frozenset({"USES_IMAGE", "PULLS_FROM", "DEPENDS_ON"})


def enrich_resource_pivots(builder: GraphBuilder) -> dict[str, int]:
    """Wire FEEDS edges from producers to consumers of intersecting resources."""
    graph = builder.snapshot
    producers = _collect_producer_scopes(graph)
    consumers = _collect_consumer_scopes(graph)
    if not producers or not consumers:
        return {"feeds_edges": 0, "producer_scopes": len(producers), "consumer_scopes": len(consumers)}

    added = 0
    for prod in producers:
        for cons in consumers:
            if prod["src_id"] == cons["src_id"]:
                continue
            hit = intersect_scopes(prod["scope"], cons["scope"])
            if not hit:
                continue
            if _add_feeds_edge(builder, graph, prod, cons, hit):
                added += 1

    return {
        "feeds_edges": added,
        "producer_scopes": len(producers),
        "consumer_scopes": len(consumers),
    }


def _collect_producer_scopes(graph: GraphSnapshot) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for edge in graph.edges:
        if edge.rel_type not in PRODUCER_RELS:
            continue
        dst = graph.nodes.get(edge.dst_id)
        dst_native = (dst.props.get("native_id") if dst else None) or edge.dst_id
        scope = scopes_from_edge_props(
            rel_type=edge.rel_type,
            props=edge.props,
            dst_native_id=dst_native,
            dst_props=dst.props if dst else {},
        )
        if not scope or scope.family not in FEEDS_FAMILIES:
            continue
        out.append(
            {
                "src_id": edge.src_id,
                "resource_node_id": edge.dst_id,
                "rel": edge.rel_type,
                "action": edge.props.get("action"),
                "scope": scope,
                "edge_confidence": edge.props.get("confidence", "explicit"),
            }
        )
    return out


def _collect_consumer_scopes(graph: GraphSnapshot) -> list[dict[str, Any]]:
    """Consumers are use-side nodes that READS/USES/PULLS/DEPENDS_ON a resource."""
    out: list[dict[str, Any]] = []
    for edge in graph.edges:
        if edge.rel_type not in CONSUMER_RELS:
            continue
        # DEPENDS_ON direction: dependent --DEPENDS_ON--> dependency (resource)
        # Consumer for pivot purposes is the dependent (edge.src).
        if not _is_use_side_consumer(graph, edge.src_id, edge.rel_type):
            continue
        dst = graph.nodes.get(edge.dst_id)
        dst_native = (dst.props.get("native_id") if dst else None) or edge.dst_id
        scope = scopes_from_edge_props(
            rel_type=edge.rel_type,
            props=edge.props,
            dst_native_id=dst_native,
            dst_props=dst.props if dst else {},
        )
        if not scope or scope.family not in FEEDS_FAMILIES:
            continue
        out.append(
            {
                "src_id": edge.src_id,
                "resource_node_id": edge.dst_id,
                "rel": edge.rel_type,
                "scope": scope,
            }
        )
    return out


def _is_use_side_consumer(graph: GraphSnapshot, src_id: str, rel_type: str) -> bool:
    """True when the edge source actually uses the resource (not just IAM can-call)."""
    if rel_type in _USE_CONSUMER_RELS:
        return True
    node = graph.nodes.get(src_id)
    if not node:
        return False
    label = str(getattr(node, "label", "") or "")
    ctype = str(node.props.get("concept_type") or "")
    if ctype in _USE_CONSUMER_CONCEPTS or label in _USE_CONSUMER_CONCEPTS:
        return True
    # Identity/Principal + READS = capability enum — do not FEEDS to these.
    return False


def _add_feeds_edge(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    prod: dict[str, Any],
    cons: dict[str, Any],
    hit: ScopeIntersection,
) -> bool:
    src_id = prod["src_id"]
    dst_id = cons["src_id"]
    # Prefer linking to the workload/image when USES_IMAGE; src is already the consumer.
    if _has_feeds(graph, src_id, dst_id, hit.scope.canonical_id):
        return False

    conf = hit.confidence
    if prod.get("edge_confidence") in {"wildcard", "unknown-conditions"}:
        conf = prod["edge_confidence"]
    if conf == "wildcard" and hit.match_kind == "type_wildcard":
        # Extremely broad (Secret:* → any secret consumer) — still emit but tagged.
        pass

    props = enrichment_edge_props(
        source="resource-pivot",
        mechanism="resource-mediated",
        capability=prod["rel"],
        consumer_rel=cons["rel"],
        action=prod.get("action"),
        via_resource=prod["resource_node_id"],
        consumer_resource=cons["resource_node_id"],
        scope_intersection=hit.scope.pattern,
        scope_canonical_id=hit.scope.canonical_id,
        match_kind=hit.match_kind,
        confidence=conf,
        resource_type=hit.scope.resource_type,
        family=hit.scope.family,
    )
    if hit.scope.path_prefix:
        props["path_prefix"] = hit.scope.path_prefix
    if hit.scope.image_tag:
        props["image_tag"] = hit.scope.image_tag

    builder.add_edge(src_id=src_id, rel_type="FEEDS", dst_id=dst_id, props=props)
    return True


def _has_feeds(graph: GraphSnapshot, src_id: str, dst_id: str, scope_id: str) -> bool:
    for dst, rel, props in graph.adjacency.get(src_id, []):
        if rel != "FEEDS" or dst != dst_id:
            continue
        if props.get("scope_canonical_id") == scope_id or props.get("via_resource"):
            # Dedup same producer→consumer for same resource family/scope.
            if props.get("scope_canonical_id") == scope_id:
                return True
    # Also dedup exact same endpoints regardless of duplicate scopes from multi-actions
    for dst, rel, props in graph.adjacency.get(src_id, []):
        if (
            rel == "FEEDS"
            and dst == dst_id
            and props.get("scope_canonical_id") == scope_id
        ):
            return True
    for edge in graph.edges:
        if (
            edge.src_id == src_id
            and edge.dst_id == dst_id
            and edge.rel_type == "FEEDS"
            and edge.props.get("scope_canonical_id") == scope_id
        ):
            return True
    return False
