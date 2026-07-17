from __future__ import annotations

from samoyed.graph.fuzzy import (
    DEFAULT_MIN_SCORE,
    fuzzy_resolve_node,
    prefer_concepts_for_material,
)
from samoyed.graph.model import GraphSnapshot


def resolve_node_ref(
    graph: GraphSnapshot,
    ref: str | None,
    *,
    prefer_concepts: tuple[str, ...] | list[str] | None = None,
    min_score: float = DEFAULT_MIN_SCORE,
) -> str | None:
    """Resolve an analyst/TF ref (ARN, native id, node id, or rough name) to a graph node id."""
    if not ref:
        return None
    raw = ref.strip()
    if not raw:
        return None

    if raw in {"caller", "start"}:
        for node_id, node in graph.nodes.items():
            if node.props.get("is_caller") or node.props.get("is_scenario_start"):
                return node_id
        return None

    if raw in graph.nodes:
        return raw

    # Fast exact / leaf pass before fuzzy scoring
    exact = _exact_resolve(graph, raw)
    if exact:
        return exact

    return fuzzy_resolve_node(
        graph,
        raw,
        min_score=min_score,
        prefer_concepts=prefer_concepts,
    )


def _exact_resolve(graph: GraphSnapshot, needle: str) -> str | None:
    from samoyed.graph.fuzzy import is_wildcard_stub

    needle_l = needle.lower()
    hits: list[str] = []
    for node_id, node in graph.nodes.items():
        if node.label == "CollectionSession" or is_wildcard_stub(node):
            continue
        props = node.props or {}
        fields = (
            node_id,
            str(props.get("arn") or ""),
            str(props.get("native_id") or ""),
            str(props.get("display_name") or ""),
            str(props.get("name") or ""),
            str(props.get("bucket_name") or ""),
            str(props.get("function_name") or ""),
            str(props.get("secret_name") or ""),
            str(props.get("db_instance_identifier") or ""),
            str(props.get("identifier") or ""),
            str(props.get("cluster_name") or ""),
            str(props.get("role_name") or ""),
        )
        if any(f and f.lower() == needle_l for f in fields):
            hits.append(node_id)
    unique = list(dict.fromkeys(hits))
    if len(unique) == 1:
        return unique[0]
    return None


__all__ = [
    "resolve_node_ref",
    "fuzzy_resolve_node",
    "prefer_concepts_for_material",
    "DEFAULT_MIN_SCORE",
]
