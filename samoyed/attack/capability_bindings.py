"""Bind IAM capability globs to inventored resources.

Policy enum often stops at ``Resource:Secret:*`` / ``S3Bucket:*``. Blast then
looks like influence over abstract stubs, not real buckets/secrets. This enricher
adds the same READS/WRITES/CONTROLS/… edges onto inventored nodes whose scopes
intersect the policy pattern so blast/FEEDS can show concrete impact.
"""

from __future__ import annotations

from typing import Any

from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.resource_scope import (
    PRODUCER_RELS,
    ResourceScope,
    intersect_scopes,
    scopes_from_edge_props,
)

# Capability edges we project onto inventory.
_CAPABILITY_RELS = frozenset({"READS", "WRITES", "DELETES", "CONTROLS", "EXECUTES"})

# Families worth expanding (poison / data / compute attachment).
_EXPAND_FAMILIES = frozenset({"s3", "secretsmanager", "ecr", "ssm"})

_EXPAND_RESOURCE_TYPES = frozenset(
    {
        "S3Bucket",
        "Secret",
        "ECRRepository",
        "SSMParameter",
        "LambdaFunction",
    }
)

_INVENTORY_CONCEPTS = frozenset(
    {
        "DataStore",
        "SecretStore",
        "RegistryStore",
        "RuntimeBinding",
    }
)


def enrich_capability_bindings(builder: GraphBuilder) -> dict[str, int]:
    """Project wildcard/pattern capability edges onto inventored resource nodes."""
    graph = builder.snapshot
    inventory = _inventory_scopes(graph)
    if not inventory:
        return {"capability_bindings": 0, "inventory_scopes": 0}

    added = 0
    for edge in list(graph.edges):
        if edge.rel_type not in _CAPABILITY_RELS:
            continue
        src = graph.nodes.get(edge.src_id)
        if not src or src.props.get("concept_type") != "Identity":
            continue
        dst = graph.nodes.get(edge.dst_id)
        dst_native = (dst.props.get("native_id") if dst else None) or edge.dst_id
        scope = scopes_from_edge_props(
            rel_type=edge.rel_type,
            props=edge.props,
            dst_native_id=dst_native,
            dst_props=dst.props if dst else {},
        )
        if not scope:
            continue
        # Only expand patterns / type wildcards — concrete edges already point somewhere.
        if not scope.is_wildcard and "*" not in scope.pattern and "*" not in scope.canonical_id:
            continue
        if scope.family not in _EXPAND_FAMILIES and scope.resource_type not in _EXPAND_RESOURCE_TYPES:
            continue

        for inv in inventory:
            if inv["node_id"] == edge.dst_id:
                continue
            hit = intersect_scopes(scope, inv["scope"])
            if not hit:
                continue
            if _add_binding(builder, graph, edge, inv["node_id"], hit.scope, hit.match_kind):
                added += 1

    return {"capability_bindings": added, "inventory_scopes": len(inventory)}


def _inventory_scopes(graph: GraphSnapshot) -> list[dict[str, Any]]:
    """Concrete inventored resources (no policy ``*`` stubs)."""
    out: list[dict[str, Any]] = []
    for node_id, node in graph.nodes.items():
        concept = str(node.props.get("concept_type") or "")
        rtype = str(node.props.get("resource_type") or "")
        native = str(node.props.get("native_id") or node_id)
        if "*" in native or native.endswith(":*"):
            continue
        if concept not in _INVENTORY_CONCEPTS and rtype not in _EXPAND_RESOURCE_TYPES:
            continue
        if rtype not in _EXPAND_RESOURCE_TYPES and not any(
            native.startswith(f"{t}:") or f":{t}:" in native for t in _EXPAND_RESOURCE_TYPES
        ):
            # Allow S3Bucket:name / Secret:arn without Resource: prefix
            if not any(tok in native for tok in ("S3Bucket", "Secret", "ECRRepository", "SSMParameter", "LambdaFunction")):
                continue
        scope = scopes_from_edge_props(
            rel_type="READS",
            props={"resource_type": rtype} if rtype else {},
            dst_native_id=native,
            dst_props=node.props,
        )
        if not scope or scope.is_wildcard:
            continue
        if scope.family not in _EXPAND_FAMILIES and scope.resource_type not in _EXPAND_RESOURCE_TYPES:
            continue
        out.append({"node_id": node_id, "scope": scope})
    return out


def _add_binding(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    edge: Any,
    inv_node_id: str,
    scope: ResourceScope,
    match_kind: str,
) -> bool:
    # Dedupe: already have same capability to this inventored node.
    for dst, rel, props in graph.adjacency.get(edge.src_id, []):
        if dst == inv_node_id and rel == edge.rel_type:
            if props.get("discovered_via") == "capability-glob" or not props.get("discovered_via"):
                # Prefer keeping an explicit edge; skip duplicate glob.
                if props.get("discovered_via") != "capability-glob" and "*" not in str(
                    props.get("resource") or props.get("scope_canonical_id") or ""
                ):
                    return False
                if props.get("discovered_via") == "capability-glob":
                    return False
    props = enrichment_edge_props(
        source="capability-bindings",
        discovered_via="capability-glob",
        mechanism="policy-resource-glob",
        action=edge.props.get("action"),
        resource=edge.props.get("resource") or scope.pattern,
        resource_type=scope.resource_type,
        scope_canonical_id=scope.canonical_id,
        match_kind=match_kind,
        confidence="wildcard" if scope.is_wildcard or match_kind == "type_wildcard" else edge.props.get(
            "confidence", "explicit"
        ),
        via_policy_resource=edge.dst_id,
        family=scope.family,
    )
    builder.add_edge(
        src_id=edge.src_id,
        rel_type=edge.rel_type,
        dst_id=inv_node_id,
        props=props,
    )
    return True
