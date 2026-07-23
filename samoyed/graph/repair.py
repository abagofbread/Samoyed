from __future__ import annotations

from samoyed.graph.model import GraphEdge, GraphNode, GraphSnapshot


INTERNET_NATIVE_ID = "network:internet"
LEGACY_EXPOSURE_PREFIX = "network:exposure:"
LEGACY_INTERNET_EXPOSURE_PREFIX = "network:exposure:internet:"


def repair_legacy_internet_exposure(graph: GraphSnapshot) -> dict[str, int]:
    """Collapse legacy per-resource exposure nodes into direct Internet edges.

    Older enrichment passes treated generated NetworkExposure nodes as resources,
    recursively producing ``internet exposure for internet exposure ...`` chains.
    This repair is intentionally idempotent and safe to run whenever a session is
    loaded.
    """
    internet_id = _find_internet_node(graph)
    legacy_ids = {
        node_id
        for node_id, node in graph.nodes.items()
        if str(node.props.get("native_id") or "").startswith(LEGACY_EXPOSURE_PREFIX)
    }
    if not legacy_ids:
        if internet_id:
            _normalize_internet_node(graph.nodes[internet_id])
        return {"removed_nodes": 0, "added_edges": 0}

    if not internet_id:
        internet_id = "Resource:network:internet"
        graph.add_node(
            GraphNode(
                node_id=internet_id,
                label="Resource",
                props={
                    "native_id": INTERNET_NATIVE_ID,
                    "display_name": "The Internet",
                    "concept_type": "NetworkExposure",
                    "resource_type": "NetworkExposure",
                    "exposure_level": "internet",
                    "source": "surface-enrichment",
                },
            )
        )
    else:
        _normalize_internet_node(graph.nodes[internet_id])

    internet_exposure_ids = {
        node_id
        for node_id in legacy_ids
        if str(graph.nodes[node_id].props.get("native_id") or "").startswith(
            LEGACY_INTERNET_EXPOSURE_PREFIX
        )
    }
    targets: set[str] = set()
    for node_id in internet_exposure_ids:
        target = _resolve_legacy_target(graph, node_id, legacy_ids)
        if target and target != internet_id and target in graph.nodes:
            targets.add(target)

    existing = {
        (edge.src_id, edge.rel_type, edge.dst_id)
        for edge in graph.edges
        if edge.src_id not in legacy_ids and edge.dst_id not in legacy_ids
    }
    added_edges = 0
    for target in sorted(targets):
        key = (internet_id, "CAN_REACH", target)
        if key in existing:
            continue
        graph.add_edge(
            GraphEdge(
                src_id=internet_id,
                rel_type="CAN_REACH",
                dst_id=target,
                props={
                    "source": "surface-enrichment",
                    "exposure_level": "internet",
                    "confidence": "explicit",
                    "repaired_from_legacy_exposure": True,
                },
            )
        )
        existing.add(key)
        added_edges += 1

    for node_id in legacy_ids:
        graph.remove_node(node_id)

    return {"removed_nodes": len(legacy_ids), "added_edges": added_edges}


def _find_internet_node(graph: GraphSnapshot) -> str | None:
    for node_id, node in graph.nodes.items():
        if node.props.get("native_id") == INTERNET_NATIVE_ID:
            return node_id
    return None


def _normalize_internet_node(node: GraphNode) -> None:
    node.props["display_name"] = "The Internet"
    node.props["concept_type"] = "NetworkExposure"
    node.props["resource_type"] = "NetworkExposure"
    node.props["exposure_level"] = "internet"


def _resolve_legacy_target(
    graph: GraphSnapshot,
    start_id: str,
    legacy_ids: set[str],
) -> str | None:
    current = start_id
    seen: set[str] = set()
    while current in legacy_ids and current not in seen:
        seen.add(current)
        node = graph.nodes.get(current)
        if not node:
            return None
        target = node.props.get("target_resource")
        if not isinstance(target, str) or not target:
            return None
        current = target
    return None if current in seen else current
