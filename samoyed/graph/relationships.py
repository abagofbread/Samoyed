from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from samoyed.graph.markings import apply_marking, find_compromised_nodes
from samoyed.graph.model import GraphEdge, GraphSnapshot

# Analyst-declared controlling dependency: dependent is downstream of dependency.
DEPENDS_ON = "DEPENDS_ON"

CompromiseFlow = Literal["downstream", "upstream", "both"]

# Enum/probe capability edges: compromised principal taints writable/controllable targets.
CAPABILITY_COMPROMISE_RELS = frozenset({"WRITES", "CONTROLS", "EXECUTES", "DELETES", "FEEDS"})

RELATIONSHIP_ALIASES: dict[str, dict[str, Any]] = {
    "depends_on": {
        "rel_type": DEPENDS_ON,
        "from": "dependent",
        "to": "dependency",
        "compromise_flow": "downstream",
        "description": "Dependent is downstream of a controlling dependency — compromise flows dependency → dependent",
    },
    "controlled_by": {
        "rel_type": DEPENDS_ON,
        "from": "dependent",
        "to": "dependency",
        "compromise_flow": "downstream",
        "description": "Same as depends_on: dependent is controlled by upstream dependency",
    },
    "downstream_of": {
        "rel_type": DEPENDS_ON,
        "from": "dependent",
        "to": "dependency",
        "compromise_flow": "downstream",
        "description": "Dependent sits downstream of dependency in blast chain",
    },
}


def normalize_relationship(name: str) -> dict[str, Any]:
    key = name.strip().lower().replace(" ", "_").replace("-", "_")
    spec = RELATIONSHIP_ALIASES.get(key)
    if not spec:
        raise ValueError(
            f"Unknown relationship '{name}'. Known: {', '.join(sorted(RELATIONSHIP_ALIASES))}"
        )
    return spec


def resolve_relationship_endpoints(
    spec: dict[str, Any],
    *,
    dependent: str | None = None,
    dependency: str | None = None,
    from_ref: str | None = None,
    to_ref: str | None = None,
    # Legacy names — dependency = upstream controller, dependent = downstream
    supplier: str | None = None,
    consumer: str | None = None,
) -> tuple[str, str]:
    """Map roles to edge direction: dependent --DEPENDS_ON--> dependency."""
    if from_ref and to_ref:
        return from_ref.strip(), to_ref.strip()

    if consumer and not dependent:
        dependent = consumer
    if supplier and not dependency:
        dependency = supplier

    role_from = spec["from"]
    role_to = spec["to"]
    role_values = {"dependent": dependent, "dependency": dependency}
    src = role_values.get(role_from)
    dst = role_values.get(role_to)
    if not src or not dst:
        raise ValueError(
            f"Relationship requires dependent and dependency refs "
            f"(or from_ref/to_ref). {spec.get('description', '')}"
        )
    return src.strip(), dst.strip()


def add_analyst_edge(
    graph: GraphSnapshot,
    *,
    src_id: str,
    dst_id: str,
    rel_type: str = DEPENDS_ON,
    source: str = "analyst",
    notes: str = "",
    relationship: str | None = None,
    compromise_flow: CompromiseFlow = "downstream",
    mark_control_point: bool = True,
) -> GraphEdge:
    if src_id not in graph.nodes:
        raise ValueError(f"Source node not found: {src_id}")
    if dst_id not in graph.nodes:
        raise ValueError(f"Destination node not found: {dst_id}")

    now = datetime.now(timezone.utc).isoformat()
    edge = GraphEdge(
        src_id=src_id,
        rel_type=rel_type,
        dst_id=dst_id,
        props={
            "source": source,
            "declared_at": now,
            "analyst_declared": True,
            "confidence": "explicit",
            "compromise_flow": compromise_flow,
            **({"relationship": relationship} if relationship else {}),
            **({"notes": notes} if notes else {}),
        },
    )
    graph.add_edge(edge)

    if mark_control_point and rel_type == DEPENDS_ON:
        dependency = graph.nodes[dst_id]
        dependency.props["is_control_point"] = True
        dependency.props.setdefault("control_point_for", [])
        if src_id not in dependency.props["control_point_for"]:
            dependency.props["control_point_for"].append(src_id)

    return edge


def _mark_propagated(
    graph: GraphSnapshot,
    node_id: str,
    *,
    via_rel: str,
    from_id: str,
    compromised_set: set[str],
    propagated: list[dict[str, Any]],
) -> None:
    node = graph.nodes.get(node_id)
    if not node or node_id in compromised_set:
        return
    apply_marking(node.props, compromised=True, source="propagation")
    node.props["compromise_propagated"] = True
    node.props["propagated_via"] = via_rel
    node.props["propagated_from"] = from_id
    compromised_set.add(node_id)
    propagated.append(
        {
            "node_id": node_id,
            "display": node.props.get("display_name") or node.props.get("native_id") or node_id,
            "propagated_via": via_rel,
            "propagated_from": from_id,
        }
    )


def propagate_compromise(graph: GraphSnapshot) -> list[dict[str, Any]]:
    """
    Expand is_compromised until fixed point.

    1. Capability edges (WRITES, etc.) from enum/probes — compromised actor taints target.
    2. DEPENDS_ON — dependent --DEPENDS_ON--> dependency (controlling node):
       default downstream flow: dependency compromised → dependent compromised.

    Example chain (leaked key → prod):
      leaked-user --WRITES--> artifact-bucket
      build-pipeline --DEPENDS_ON--> artifact-bucket
      prod-workloads --DEPENDS_ON--> build-pipeline
    """
    propagated: list[dict[str, Any]] = []
    compromised_set = set(find_compromised_nodes(graph))

    while True:
        newly_marked: list[tuple[str, str, str]] = []

        for edge in graph.edges:
            if edge.rel_type in CAPABILITY_COMPROMISE_RELS:
                if edge.src_id in compromised_set and edge.dst_id not in compromised_set:
                    newly_marked.append((edge.dst_id, edge.rel_type, edge.src_id))
                continue

            if edge.rel_type != DEPENDS_ON:
                continue

            flow: str = edge.props.get("compromise_flow", "downstream")
            if flow in ("downstream", "both"):
                if edge.dst_id in compromised_set and edge.src_id not in compromised_set:
                    newly_marked.append((edge.src_id, edge.rel_type, edge.dst_id))
            if flow in ("upstream", "both"):
                if edge.src_id in compromised_set and edge.dst_id not in compromised_set:
                    newly_marked.append((edge.dst_id, edge.rel_type, edge.src_id))

        if not newly_marked:
            break

        for node_id, via_rel, from_id in newly_marked:
            _mark_propagated(
                graph,
                node_id,
                via_rel=via_rel,
                from_id=from_id,
                compromised_set=compromised_set,
                propagated=propagated,
            )

    return propagated


def list_declared_relationships(graph: GraphSnapshot) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for edge in graph.edges:
        if not edge.props.get("analyst_declared"):
            continue
        src = graph.nodes.get(edge.src_id)
        dst = graph.nodes.get(edge.dst_id)
        out.append(
            {
                "dependent_id": edge.src_id,
                "dependent_display": (src.props.get("display_name") if src else None) or edge.src_id,
                "dependency_id": edge.dst_id,
                "dependency_display": (dst.props.get("display_name") if dst else None) or edge.dst_id,
                "rel": edge.rel_type,
                "compromise_flow": edge.props.get("compromise_flow", "downstream"),
                **edge.props,
            }
        )
    return out
