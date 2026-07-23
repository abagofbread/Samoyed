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
    CONSUMER_RELS,
    ResourceScope,
    intersect_scopes,
    scopes_from_edge_props,
)

# Capability edges we project onto inventory.
_CAPABILITY_RELS = frozenset({"READS", "WRITES", "DELETES", "CONTROLS", "EXECUTES"})

# Families worth expanding (poison / data / compute attachment).
_EXPAND_FAMILIES = frozenset(
    {"s3", "secretsmanager", "ecr", "ssm", "rds", "dynamodb", "kms", "lambda", "ec2"}
)

_EXPAND_RESOURCE_TYPES = frozenset(
    {
        "S3Bucket",
        "Secret",
        "ECRRepository",
        "SSMParameter",
        "LambdaFunction",
        "Lambda",
        "EC2Instance",
        "RDSInstance",
        "Rds",
        "RDS",
        "DBInstance",
        "DynamoDBTable",
        "DynamoDB",
        "KMSKey",
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

_INVENTORY_NATIVE_TOKENS = (
    "S3Bucket",
    "Secret",
    "ECRRepository",
    "SSMParameter",
    "LambdaFunction",
    "EC2Instance",
    "RDSInstance",
    "Rds",
    "DynamoDBTable",
    "DynamoDB",
    "KMSKey",
)


def enrich_capability_bindings(builder: GraphBuilder) -> dict[str, int]:
    """Project wildcard/pattern capability edges onto inventored resource nodes."""
    graph = builder.snapshot
    pruned = _prune_unused_secret_bindings(graph)
    inventory = _inventory_scopes(graph)
    if not inventory:
        return {
            "capability_bindings": 0,
            "inventory_scopes": 0,
            "unused_secret_bindings_pruned": pruned,
        }

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

    return {
        "capability_bindings": added,
        "inventory_scopes": len(inventory),
        "unused_secret_bindings_pruned": pruned,
    }


def _prune_unused_secret_bindings(graph: GraphSnapshot) -> int:
    """Drop capability-glob edges to inventored secrets with no use or impact."""
    remove: list[tuple[str, str, str]] = []
    for edge in graph.edges:
        if edge.props.get("discovered_via") != "capability-glob":
            continue
        if edge.rel_type not in _CAPABILITY_RELS:
            continue
        dst = graph.nodes.get(edge.dst_id)
        if not dst or not _is_secret_node(dst):
            continue
        if _secret_has_use_side_consumer(graph, edge.dst_id):
            continue
        if _secret_unlocks_impact(graph, edge.dst_id):
            continue
        remove.append((edge.src_id, edge.rel_type, edge.dst_id))
    for src, rel, dst in remove:
        graph.remove_edge(src, rel, dst)
    return len(remove)


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
            if not any(tok in native for tok in _INVENTORY_NATIVE_TOKENS):
                # RDS inventored via db_instance_identifier without typed prefix.
                if not (
                    node.props.get("db_instance_identifier")
                    or rtype in {"RDSInstance", "Rds", "DBInstance"}
                ):
                    continue
        scope = scopes_from_edge_props(
            rel_type="READS",
            props={"resource_type": rtype} if rtype else {},
            dst_native_id=native,
            dst_props=node.props,
        )
        if not scope:
            # Project RDS scope from identifier props when native_id is opaque.
            db_id = node.props.get("db_instance_identifier") or node.props.get("name")
            if db_id and (
                rtype in {"RDSInstance", "Rds", "DBInstance"}
                or concept == "DataStore"
            ):
                scope = ResourceScope(
                    "rds",
                    "RDSInstance",
                    f"RDSInstance:{db_id}",
                    str(db_id),
                )
            else:
                continue
        # Project EC2 scope from instance_id when native_id is opaque.
        if scope.family == "other" and (
            rtype == "EC2Instance" or node.props.get("instance_id")
        ):
            iid = node.props.get("instance_id") or node.props.get("name")
            if iid and "*" not in str(iid):
                scope = ResourceScope("ec2", "EC2Instance", f"EC2Instance:{iid}", str(iid))
        if scope.is_wildcard:
            continue
        if scope.family not in _EXPAND_FAMILIES and scope.resource_type not in _EXPAND_RESOURCE_TYPES:
            continue
        # Secrets: expand when used by a workload OR when the vault unlocks a
        # typed impact target (e.g. RDS_CREDS → aws-goat-db).
        if scope.family == "secretsmanager" and not (
            _secret_has_use_side_consumer(graph, node_id)
            or _secret_unlocks_impact(graph, node_id)
        ):
            continue
        out.append({"node_id": node_id, "scope": scope})
    return out


def _is_secret_node(node: Any) -> bool:
    concept = str(node.props.get("concept_type") or "")
    rtype = str(node.props.get("resource_type") or "")
    native = str(node.props.get("native_id") or "")
    return concept == "SecretStore" or rtype == "Secret" or native.startswith("Secret:")


def _secret_has_use_side_consumer(graph: GraphSnapshot, secret_node_id: str) -> bool:
    """True when a workload/runtime READS/DEPENDS_ON this inventored secret."""
    use_concepts = frozenset(
        {"Workload", "RuntimeBinding", "ImageProvenance", "RegistryStore"}
    )
    for edge in graph.edges:
        if edge.dst_id != secret_node_id or edge.rel_type not in CONSUMER_RELS:
            continue
        src = graph.nodes.get(edge.src_id)
        if not src:
            continue
        concept = str(src.props.get("concept_type") or "")
        label = str(getattr(src, "label", "") or "")
        if concept in use_concepts or label in use_concepts:
            return True
    return False


def _secret_unlocks_impact(graph: GraphSnapshot, secret_node_id: str) -> bool:
    """True when this vault UNLOCKS a typed target (password-in-secrets story)."""
    for dst, rel, props in graph.adjacency.get(secret_node_id, []):
        if rel != "UNLOCKS":
            continue
        if props.get("mechanism") in {
            "secret-store-yields-credential",
            "secret-scope-yields-credential",
            "credential-impact",
        }:
            return True
        dst_node = graph.nodes.get(dst)
        if dst_node and not (
            dst_node.props.get("native_kind") == "PivotMaterial"
            or dst_node.props.get("material_kind")
        ):
            return True
    return False


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
