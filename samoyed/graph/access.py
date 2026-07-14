from __future__ import annotations

from typing import Any, Literal

GraphAccessLevel = Literal["full", "summary", "compare_only"]
GraphRole = Literal["canon", "proposed", "interactive", "ephemeral"]

DEFAULT_ACCESS_BY_ROLE: dict[str, GraphAccessLevel] = {
    "canon": "full",
    "interactive": "full",
    "proposed": "compare_only",
    "ephemeral": "compare_only",
}


def graph_access_for_metadata(metadata: dict[str, Any] | None) -> GraphAccessLevel:
    meta = metadata or {}
    explicit = meta.get("graph_access")
    if explicit in {"full", "summary", "compare_only"}:
        return explicit  # type: ignore[return-value]
    role = meta.get("graph_role")
    if role in DEFAULT_ACCESS_BY_ROLE:
        return DEFAULT_ACCESS_BY_ROLE[role]
    return "full"


def graph_summary(snapshot) -> dict[str, Any]:
    nodes = [n for n in snapshot.nodes.values() if n.label != "CollectionSession"]
    edges = snapshot.edges
    concepts: dict[str, int] = {}
    for node in nodes:
        concept = str(node.props.get("concept_type") or node.label)
        concepts[concept] = concepts.get(concept, 0) + 1
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "concepts": concepts,
    }


def filter_graph_payload(
    snapshot,
    *,
    access: GraphAccessLevel,
) -> dict[str, Any]:
    if access == "full":
        return {
            "access": "full",
            "nodes": [
                {"id": n.node_id, "label": n.label, **n.props}
                for n in snapshot.nodes.values()
                if n.label != "CollectionSession"
            ],
            "edges": [
                {"src": e.src_id, "rel": e.rel_type, "dst": e.dst_id, **e.props}
                for e in snapshot.edges
            ],
        }
    if access == "summary":
        return {"access": "summary", **graph_summary(snapshot)}
    return {
        "access": "compare_only",
        "message": "Full graph withheld — use POST /api/sessions/compare for attack-surface diff.",
        **graph_summary(snapshot),
    }
