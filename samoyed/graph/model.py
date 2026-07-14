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

    def remove_edge(self, src_id: str, rel_type: str, dst_id: str) -> bool:
        before = len(self.edges)
        self.edges = [
            edge
            for edge in self.edges
            if not (edge.src_id == src_id and edge.rel_type == rel_type and edge.dst_id == dst_id)
        ]
        if len(self.edges) == before:
            return False
        if src_id in self.adjacency:
            self.adjacency[src_id] = [
                (dst, rel, props)
                for dst, rel, props in self.adjacency[src_id]
                if not (dst == dst_id and rel == rel_type)
            ]
        return True

    def remove_node(self, node_id: str) -> bool:
        if node_id not in self.nodes:
            return False
        self.edges = [
            edge for edge in self.edges if edge.src_id != node_id and edge.dst_id != node_id
        ]
        del self.nodes[node_id]
        self.adjacency.pop(node_id, None)
        for src_id, entries in list(self.adjacency.items()):
            self.adjacency[src_id] = [
                (dst, rel, props) for dst, rel, props in entries if dst != node_id
            ]
        return True
