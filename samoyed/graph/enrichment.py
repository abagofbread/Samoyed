from __future__ import annotations

from typing import Any

ENRICHMENT_EDGE_ORIGIN = "enrichment"

ENRICHMENT_EDGE_SOURCES = frozenset(
    {
        "surface-enrichment",
        "pivot-enrichment",
        "enrichment",
        "host-pivot",
        "collector",
        "collector-enrichment",
        "collector-declared",
        "k8s-deploy-pivot",
        "k8s-rbac-enum",
        "high-value-catalog",
        "service-admin-catalog",
        "shadow-admin",
        "resource-pivot",
        "shared-across-envs",
        "capability-bindings",
    }
)

PIVOT_REL_TYPES = frozenset(
    {
        "HAS_MATERIAL",
        "UNLOCKS",
        "MOUNTED_INTO",
        "REFERENCES",
        "LOGGED_IN_AS",
        "STORES_CREDS_FOR",
        "CAN_STEAL_CREDS_FROM",
        "FEEDS",
    }
)


def enrichment_edge_props(**extra: Any) -> dict[str, Any]:
    """Standard props for edges added by surface/pivot/collector enrichment (not raw IAM enum)."""
    props = {"edge_origin": ENRICHMENT_EDGE_ORIGIN}
    props.update(extra)
    return props


def is_enrichment_edge(rel_type: str, props: dict[str, Any] | None) -> bool:
    """Whether an edge was derived from enrichment rather than direct authorization enum."""
    props = props or {}
    if props.get("edge_origin") == ENRICHMENT_EDGE_ORIGIN or props.get("is_enrichment"):
        return True
    source = props.get("source")
    if source in ENRICHMENT_EDGE_SOURCES:
        return True
    if rel_type in PIVOT_REL_TYPES:
        return True
    if rel_type == "CAN_ESCAPE_TO" and props.get("mechanism"):
        return True
    if rel_type == "HAS_ESCAPE_SURFACE" and source in ENRICHMENT_EDGE_SOURCES:
        return True
    if rel_type == "EXECUTES_AS" and (
        source in ENRICHMENT_EDGE_SOURCES
        or str(props.get("mechanism", "")).startswith("imds")
        or str(props.get("mechanism", "")).startswith("k8s-")
    ):
        return True
    if rel_type == "CAN_REACH" and source in ENRICHMENT_EDGE_SOURCES:
        return True
    return False


def mark_enrichment_edges(graph: Any) -> int:
    """Tag derived edges with edge_origin so the UI can style them consistently."""
    marked = 0
    for edge in graph.edges:
        if not is_enrichment_edge(edge.rel_type, edge.props):
            continue
        if edge.props.get("edge_origin") == ENRICHMENT_EDGE_ORIGIN:
            continue
        edge.props["edge_origin"] = ENRICHMENT_EDGE_ORIGIN
        marked += 1
    return marked
