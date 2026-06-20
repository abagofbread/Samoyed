from __future__ import annotations

from typing import Any, Literal

from samoyed.graph.model import GraphSnapshot


def _node_display(graph: GraphSnapshot, node_id: str) -> str:
    node = graph.nodes.get(node_id)
    if not node:
        return node_id
    name = node.props.get("display_name") or node.props.get("native_id") or node.props.get("arn")
    if name:
        return str(name)
    return node_id


def get_neighbors(
    graph: GraphSnapshot,
    node_id: str,
    *,
    rel_type: str | None = None,
    direction: Literal["out", "in", "both"] = "out",
) -> list[dict[str, Any]]:
    if node_id not in graph.nodes:
        return []

    neighbors: list[dict[str, Any]] = []
    if direction in {"out", "both"}:
        for dst_id, edge_rel, props in graph.adjacency.get(node_id, []):
            if rel_type and edge_rel != rel_type:
                continue
            dst = graph.nodes.get(dst_id)
            neighbors.append(
                {
                    "direction": "out",
                    "rel_type": edge_rel,
                    "node_id": dst_id,
                    "label": dst.label if dst else "Unknown",
                    "props": dst.props if dst else {},
                    "edge_props": props,
                }
            )

    if direction in {"in", "both"}:
        for edge in graph.edges:
            if edge.dst_id != node_id:
                continue
            if rel_type and edge.rel_type != rel_type:
                continue
            src = graph.nodes.get(edge.src_id)
            neighbors.append(
                {
                    "direction": "in",
                    "rel_type": edge.rel_type,
                    "node_id": edge.src_id,
                    "label": src.label if src else "Unknown",
                    "props": src.props if src else {},
                    "edge_props": edge.props,
                }
            )
    return neighbors
