from __future__ import annotations

from samoyed.graph.model import GraphSnapshot


def resolve_node_ref(graph: GraphSnapshot, ref: str | None) -> str | None:
    """Resolve an analyst ref (ARN, native id, node id, or substring) to a graph node id."""
    if not ref:
        return None
    if ref in {"caller", "start"}:
        for node_id, node in graph.nodes.items():
            if node.props.get("is_caller") or node.props.get("is_scenario_start"):
                return node_id
        return None

    needle = ref.strip()
    if needle in graph.nodes:
        return needle

    needle_lower = needle.lower()
    exact: list[str] = []
    partial: list[str] = []
    for node_id, node in graph.nodes.items():
        if node.label == "CollectionSession":
            continue
        fields = (
            node_id,
            str(node.props.get("arn") or ""),
            str(node.props.get("native_id") or ""),
            str(node.props.get("display_name") or ""),
            str(node.props.get("name") or ""),
            str(node.props.get("bucket_name") or ""),
            str(node.props.get("function_name") or ""),
        )
        if any(f and f.lower() == needle_lower for f in fields):
            exact.append(node_id)
            continue
        if any(
            f
            and (needle_lower in f.lower() or f.lower().endswith(needle_lower.split("/")[-1]))
            for f in fields
            if f
        ):
            partial.append(node_id)

    for bucket in (exact, partial):
        unique = list(dict.fromkeys(bucket))
        if len(unique) == 1:
            return unique[0]
    return None
