from __future__ import annotations

from collections import Counter
from typing import Any

from samoyed.graph.model import GraphSnapshot


def format_path_query_response(
    *,
    session_id: str,
    graph: GraphSnapshot,
    start_node_id: str,
    mode: str,
    raw: dict[str, Any],
    query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Shape path/blast results for CLI, SOAR, and jq pipelines."""
    paths = [_enrich_path(p, graph) for p in raw.get("paths") or []]
    summary = _build_summary(paths)
    targets = _build_targets(paths, graph)

    return {
        "session_id": session_id,
        "mode": mode,
        "start": start_node_id,
        "start_display": _node_display(graph, start_node_id),
        "query": query or {},
        "summary": summary,
        "targets": targets,
        "paths": paths,
        **{k: v for k, v in raw.items() if k not in {"paths", "mode", "start"}},
    }


def _build_summary(paths: list[dict[str, Any]]) -> dict[str, Any]:
    if not paths:
        return {
            "path_count": 0,
            "unique_targets": 0,
            "max_score": 0.0,
            "by_target_concept": {},
            "by_relation": {},
        }
    concepts = Counter(p.get("target_concept") or "Unknown" for p in paths)
    relations = Counter(rel for p in paths for rel in p.get("relations") or [])
    scores = [float(p.get("score") or 0) for p in paths]
    end_ids = {p.get("end") for p in paths if p.get("end")}
    return {
        "path_count": len(paths),
        "unique_targets": len(end_ids),
        "max_score": max(scores),
        "min_score": min(scores),
        "by_target_concept": dict(concepts),
        "by_relation": dict(relations),
    }


def _build_targets(paths: list[dict[str, Any]], graph: GraphSnapshot) -> list[dict[str, Any]]:
    by_end: dict[str, dict[str, Any]] = {}
    for path in paths:
        end = path.get("end")
        if not end:
            continue
        entry = by_end.get(end)
        score = float(path.get("score") or 0)
        if not entry:
            by_end[end] = {
                "node_id": end,
                "display": path.get("end_display") or _node_display(graph, end),
                "concept": path.get("target_concept"),
                "resource_type": path.get("target_resource_type"),
                "best_score": score,
                "path_count": 1,
            }
        else:
            entry["path_count"] += 1
            entry["best_score"] = max(entry["best_score"], score)
    return sorted(by_end.values(), key=lambda t: (-t["best_score"], t["display"] or t["node_id"]))


def _enrich_path(path: dict[str, Any], graph: GraphSnapshot) -> dict[str, Any]:
    steps = path.get("steps") or []
    node_ids = path.get("node_ids") or []
    relations = [s.get("rel") or s.get("rel_type") for s in steps if s.get("rel") or s.get("rel_type")]
    end = node_ids[-1] if node_ids else None
    target = path.get("target_match") or {}

    displays = [_node_display(graph, nid) for nid in node_ids]
    chain_parts: list[str] = []
    for i, label in enumerate(displays):
        chain_parts.append(label)
        if i < len(relations):
            chain_parts.append(relations[i])
    chain = " → ".join(chain_parts)

    return {
        **path,
        "length": len(steps),
        "start": node_ids[0] if node_ids else None,
        "start_display": _node_display(graph, node_ids[0]) if node_ids else None,
        "end": end,
        "end_display": _node_display(graph, end) if end else None,
        "target_concept": target.get("concept_type"),
        "target_resource_type": target.get("resource_type"),
        "relations": relations,
        "chain": chain,
    }


def _node_display(graph: GraphSnapshot, node_id: str | None) -> str:
    if not node_id:
        return ""
    node = graph.nodes.get(node_id)
    if not node:
        return _short_id(node_id)
    for key in ("display_name", "name", "arn", "native_id", "bucket_name", "function_name"):
        val = node.props.get(key)
        if val:
            return str(val)
    return _short_id(node_id)


def _short_id(node_id: str) -> str:
    if "/" in node_id:
        return node_id.rsplit("/", 1)[-1]
    if ":" in node_id and node_id.count(":") >= 5:
        return node_id.rsplit(":", 1)[-1]
    if node_id.startswith("S3Bucket:"):
        return node_id.split(":", 1)[-1]
    if node_id.startswith("Secret:"):
        return node_id.rsplit(":", 1)[-1].split("-")[0] or node_id
    return node_id
