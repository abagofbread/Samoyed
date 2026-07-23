"""Remove redundant attack-path edges after enum + analysis.

Rules:
1. Collapse identical ``(src, rel, dst)`` duplicates (keep one; merge ``action`` lists).
2. Drop ``CAN_ASSUME_ROLE`` when ``CAN_PRIVESC_TO`` already exists for the same
   endpoints — assume is the weaker, redundant pivot once privesc is materialised.
3. Drop ``CONTROLS`` / ``EXECUTES`` onto an Identity when ``CAN_PRIVESC_TO`` already
   targets that same Identity (PassRole / create-key substrate duplicated as privesc).
"""

from __future__ import annotations

from typing import Any

from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphEdge, GraphSnapshot


def dedupe_redundant_edges(builder: GraphBuilder) -> dict[str, int]:
    graph = builder.snapshot
    before = len(graph.edges)

    collapsed = _collapse_identical_edges(graph)
    dropped_assume = _drop_assume_when_privesc(graph)
    dropped_cap = _drop_identity_capability_when_privesc(graph)

    _rebuild_adjacency(graph)
    return {
        "edges_before_dedupe": before,
        "edges_after_dedupe": len(graph.edges),
        "identical_collapsed": collapsed,
        "assume_dropped_for_privesc": dropped_assume,
        "identity_capability_dropped_for_privesc": dropped_cap,
    }


def _collapse_identical_edges(graph: GraphSnapshot) -> int:
    """One edge per (src, rel, dst); merge action evidence."""
    buckets: dict[tuple[str, str, str], list[GraphEdge]] = {}
    for edge in graph.edges:
        key = (edge.src_id, edge.rel_type, edge.dst_id)
        buckets.setdefault(key, []).append(edge)

    new_edges: list[GraphEdge] = []
    collapsed = 0
    for (_src, _rel, _dst), group in buckets.items():
        if len(group) == 1:
            new_edges.append(group[0])
            continue
        collapsed += len(group) - 1
        primary = group[0]
        actions: list[str] = []
        for edge in group:
            act = edge.props.get("action")
            if act:
                actions.append(str(act))
            for extra in edge.props.get("actions") or []:
                actions.append(str(extra))
        props = dict(primary.props)
        if actions:
            props["actions"] = list(dict.fromkeys(actions))
            if "action" not in props and actions:
                props["action"] = actions[0]
        props["deduped_count"] = len(group)
        new_edges.append(
            GraphEdge(
                src_id=primary.src_id,
                rel_type=primary.rel_type,
                dst_id=primary.dst_id,
                props=props,
            )
        )
    graph.edges = new_edges
    return collapsed


_ASSUME_LIKE_TOKENS = (
    "passrole",
    "assume-role",
    "assumerole",
    "update-assume",
    "updateassumerole",
    "create-access-key",
    "createaccesskey",
    "create-login-profile",
)


def _privesc_subsumes_assume(props: dict[str, Any]) -> bool:
    """True when the privesc edge is itself an assume/PassRole-style pivot."""
    blob = f"{props.get('pattern_id') or ''} {props.get('pattern_name') or ''}".lower()
    return any(tok in blob for tok in _ASSUME_LIKE_TOKENS)


def _drop_assume_when_privesc(graph: GraphSnapshot) -> int:
    """Drop CAN_ASSUME_ROLE only when a PassRole/assume-style CAN_PRIVESC_TO covers it.

    Do *not* drop trust edges just because UFC/code-takeover also lands on the same
    role — those are different mechanisms.
    """
    subsuming = {
        (e.src_id, e.dst_id)
        for e in graph.edges
        if e.rel_type == "CAN_PRIVESC_TO" and _privesc_subsumes_assume(e.props)
    }
    if not subsuming:
        return 0
    kept: list[GraphEdge] = []
    dropped = 0
    for edge in graph.edges:
        if edge.rel_type == "CAN_ASSUME_ROLE" and (edge.src_id, edge.dst_id) in subsuming:
            dropped += 1
            continue
        kept.append(edge)
    graph.edges = kept
    return dropped


def _drop_identity_capability_when_privesc(graph: GraphSnapshot) -> int:
    """PassRole CONTROLS → Role is redundant once PassRole-style CAN_PRIVESC_TO exists."""
    subsuming: set[tuple[str, str]] = set()
    for edge in graph.edges:
        if edge.rel_type != "CAN_PRIVESC_TO":
            continue
        if not _privesc_subsumes_assume(edge.props):
            continue
        dst = graph.nodes.get(edge.dst_id)
        if dst and dst.props.get("concept_type") == "Identity":
            subsuming.add((edge.src_id, edge.dst_id))
    if not subsuming:
        return 0

    kept: list[GraphEdge] = []
    dropped = 0
    for edge in graph.edges:
        if edge.rel_type not in {"CONTROLS", "EXECUTES"}:
            kept.append(edge)
            continue
        if (edge.src_id, edge.dst_id) not in subsuming:
            kept.append(edge)
            continue
        dst = graph.nodes.get(edge.dst_id)
        if not dst or dst.props.get("concept_type") != "Identity":
            kept.append(edge)
            continue
        # Keep broad IAM:* style grants (not the PassRole-to-this-role edge).
        action = str(edge.props.get("action") or "").lower()
        rtype = str(edge.props.get("resource_type") or dst.props.get("native_kind") or "")
        if action in {"iam:*", "*"} or rtype in {"IAM", "Policy"}:
            kept.append(edge)
            continue
        dropped += 1
    graph.edges = kept
    return dropped


def _rebuild_adjacency(graph: GraphSnapshot) -> None:
    graph.adjacency = {node_id: [] for node_id in graph.nodes}
    for edge in graph.edges:
        graph.adjacency.setdefault(edge.src_id, []).append(
            (edge.dst_id, edge.rel_type, edge.props)
        )
