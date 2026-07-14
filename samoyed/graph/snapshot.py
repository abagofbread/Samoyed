from __future__ import annotations

import copy

from samoyed.graph.model import GraphEdge, GraphNode, GraphSnapshot


def copy_snapshot(graph: GraphSnapshot) -> GraphSnapshot:
    """Deep-copy a graph snapshot for hypothetical change analysis."""
    cloned = GraphSnapshot(session_id=graph.session_id)
    for node in graph.nodes.values():
        cloned.add_node(
            GraphNode(
                node_id=node.node_id,
                label=node.label,
                props=copy.deepcopy(node.props),
            )
        )
    for edge in graph.edges:
        cloned.add_edge(
            GraphEdge(
                src_id=edge.src_id,
                rel_type=edge.rel_type,
                dst_id=edge.dst_id,
                props=copy.deepcopy(edge.props),
            )
        )
    return cloned
