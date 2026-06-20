from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import GraphEdge, GraphNode, GraphSnapshot


def snapshot_to_dict(snapshot: GraphSnapshot) -> dict[str, Any]:
    return {
        "session_id": snapshot.session_id,
        "nodes": [
            {"id": n.node_id, "label": n.label, **n.props} for n in snapshot.nodes.values()
        ],
        "edges": [
            {"src": e.src_id, "rel": e.rel_type, "dst": e.dst_id, **e.props} for e in snapshot.edges
        ],
    }


def snapshot_from_dict(data: dict[str, Any]) -> GraphSnapshot:
    session_id = data["session_id"]
    snapshot = GraphSnapshot(session_id=session_id)
    id_map: dict[str, str] = {}
    for node in data.get("nodes", []):
        node_id = node["id"]
        label = node.get("label", "Unknown")
        props = {k: v for k, v in node.items() if k not in {"id", "label"}}
        snapshot.add_node(GraphNode(node_id=node_id, label=label, props=props))
        id_map[node_id] = node_id
    for edge in data.get("edges", []):
        src = edge["src"]
        dst = edge["dst"]
        rel = edge["rel"]
        props = {k: v for k, v in edge.items() if k not in {"src", "rel", "dst"}}
        snapshot.add_edge(GraphEdge(src_id=src, rel_type=rel, dst_id=dst, props=props))
    return snapshot


def default_session_dir() -> Path:
    return Path.cwd() / ".samoyed" / "sessions"


def write_session_file(record_dict: dict[str, Any], directory: Path | None = None) -> Path:
    directory = directory or default_session_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{record_dict['session_id']}.json"
    path.write_text(json.dumps(record_dict, default=str), encoding="utf-8")
    return path


def read_session_file(session_id: str, directory: Path | None = None) -> dict[str, Any] | None:
    directory = directory or default_session_dir()
    path = directory / f"{session_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
