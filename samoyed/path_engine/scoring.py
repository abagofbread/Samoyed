from __future__ import annotations

CAPABILITY_WEIGHT = {
    "EXECUTES": 1.0,
    "CONTROLS": 0.9,
    "WRITES": 0.7,
    "DELETES": 0.7,
    "READS": 0.5,
    "CAN_ASSUME_ROLE": 0.85,
    "CAN_PRIVESC_TO": 0.98,
    "EXECUTES_AS": 0.92,
    "LOGGED_IN_AS": 0.88,
    "STORES_CREDS_FOR": 0.86,
    "CAN_STEAL_CREDS_FROM": 0.9,
    "CAN_ESCAPE_TO": 0.95,
    "CAN_ACCESS": 0.9,
    "PROJECTS_TO": 0.85,
    "USES_IMAGE": 0.6,
    "PULLS_FROM": 0.6,
    "CAN_REACH": 0.4,
    "HAS_ESCAPE_SURFACE": 0.3,
}


def score_path(rel_types: list[str], edge_props: list[dict]) -> float:
    if not rel_types:
        return 0.0
    base = sum(CAPABILITY_WEIGHT.get(r, 0.3) for r in rel_types) / len(rel_types)
    penalty = 0.0
    for props in edge_props:
        if props.get("confidence") == "wildcard":
            penalty += 0.05
        if props.get("confidence") == "unknown-conditions":
            penalty += 0.1
    hop_penalty = max(0, len(rel_types) - 3) * 0.03
    return round(max(0.0, min(1.0, base - penalty - hop_penalty)), 3)
