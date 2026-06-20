from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphNode:
    node_id: str
    label: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    src_id: str
    rel_type: str
    dst_id: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphSnapshot:
    session_id: str
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    adjacency: dict[str, list[tuple[str, str, dict[str, Any]]]] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.node_id] = node
        self.adjacency.setdefault(node.node_id, [])

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        self.adjacency.setdefault(edge.src_id, []).append((edge.dst_id, edge.rel_type, edge.props))
        if edge.dst_id not in self.nodes:
            self.add_node(GraphNode(node_id=edge.dst_id, label="Unknown", props={}))
