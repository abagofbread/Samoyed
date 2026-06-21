from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from samoyed.graph.model import GraphSnapshot

DEFAULT_BLAST_CONCEPTS = ["AttackOutcome", "SecretStore", "DataStore", "Identity"]

MARKING_COMPROMISED = "is_compromised"
MARKING_HIGH_VALUE = "is_high_value"


def is_compromised(props: dict[str, Any]) -> bool:
    return bool(
        props.get(MARKING_COMPROMISED)
        or props.get("is_caller")
        or props.get("is_scenario_start")
    )


def is_high_value(props: dict[str, Any]) -> bool:
    return bool(props.get(MARKING_HIGH_VALUE))


def find_compromised_nodes(graph: GraphSnapshot) -> list[str]:
    return [
        node_id
        for node_id, node in graph.nodes.items()
        if node.label != "CollectionSession" and is_compromised(node.props)
    ]


def find_high_value_nodes(graph: GraphSnapshot) -> list[str]:
    return [
        node_id
        for node_id, node in graph.nodes.items()
        if node.label != "CollectionSession" and is_high_value(node.props)
    ]


def apply_marking(
    props: dict[str, Any],
    *,
    compromised: bool | None = None,
    high_value: bool | None = None,
    source: str = "analyst",
    clear: bool = False,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    if compromised is not None:
        if compromised:
            props[MARKING_COMPROMISED] = True
            props["marking_source"] = source
            props["marked_at"] = now
        elif clear or compromised is False:
            props.pop(MARKING_COMPROMISED, None)
    if high_value is not None:
        if high_value:
            props[MARKING_HIGH_VALUE] = True
            props["marking_source"] = source
            props["marked_at"] = now
        elif clear or high_value is False:
            props.pop(MARKING_HIGH_VALUE, None)


def summarize_markings(graph: GraphSnapshot) -> dict[str, Any]:
    compromised: list[dict[str, Any]] = []
    high_value: list[dict[str, Any]] = []
    for node_id, node in graph.nodes.items():
        if node.label == "CollectionSession":
            continue
        entry = {
            "node_id": node_id,
            "display": node.props.get("display_name")
            or node.props.get("native_id")
            or node.props.get("arn")
            or node_id,
            "concept_type": node.props.get("concept_type"),
            "marking_source": node.props.get("marking_source"),
        }
        if is_compromised(node.props):
            compromised.append(entry)
        if is_high_value(node.props):
            high_value.append(entry)
    return {
        "compromised_count": len(compromised),
        "high_value_count": len(high_value),
        "compromised": compromised,
        "high_value": high_value,
    }
