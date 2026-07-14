from __future__ import annotations

from samoyed.graph.model import GraphNode, GraphSnapshot


def node_stable_key(node: GraphNode, node_id: str | None = None) -> str:
    """Cross-graph identity for the same cloud resource (ARN, native id, etc.)."""
    nid = node_id or node.node_id
    for key in ("native_id", "arn", "bucket_name", "function_name", "name"):
        value = node.props.get(key)
        if value and str(value).strip():
            return str(value).strip()
    if node.props.get("display_name"):
        return str(node.props["display_name"]).strip()
    return nid


def stable_key_for_id(graph: GraphSnapshot, node_id: str) -> str:
    node = graph.nodes.get(node_id)
    if not node:
        return node_id
    return node_stable_key(node, node_id)


def display_for_id(graph: GraphSnapshot, node_id: str) -> str:
    node = graph.nodes.get(node_id)
    if not node:
        return node_id
    return str(
        node.props.get("display_name")
        or node.props.get("name")
        or node.props.get("bucket_name")
        or node.props.get("function_name")
        or node_stable_key(node, node_id)
    )
