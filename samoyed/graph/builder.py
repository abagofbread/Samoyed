from __future__ import annotations

import hashlib
import json
from typing import Any

from samoyed.cloud.concepts import CONCEPT_TO_NODE_LABEL, ConceptType

from .model import GraphEdge, GraphNode, GraphSnapshot


def stable_id(*parts: str) -> str:
    raw = ":".join(parts)
    if len(raw) <= 120:
        return raw
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"{parts[0]}:{digest}"


class GraphBuilder:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.snapshot = GraphSnapshot(session_id=session_id)

    def add_concept_node(
        self,
        *,
        concept_type: ConceptType,
        native_id: str,
        props: dict[str, Any] | None = None,
    ) -> str:
        label = CONCEPT_TO_NODE_LABEL.get(concept_type, concept_type.value)
        node_id = stable_id(label, native_id)
        merged = {"concept_type": concept_type.value, "native_id": native_id, **(props or {})}
        self.snapshot.add_node(GraphNode(node_id=node_id, label=label, props=merged))
        return node_id

    def add_edge(
        self,
        *,
        src_id: str,
        rel_type: str,
        dst_id: str,
        props: dict[str, Any] | None = None,
    ) -> None:
        self.snapshot.add_edge(
            GraphEdge(src_id=src_id, rel_type=rel_type, dst_id=dst_id, props=props or {})
        )

    def link_session(self, node_id: str) -> None:
        session_node = stable_id("CollectionSession", self.session_id)
        if session_node not in self.snapshot.nodes:
            self.snapshot.add_node(
                GraphNode(
                    node_id=session_node,
                    label="CollectionSession",
                    props={"session_id": self.session_id},
                )
            )
        self.add_edge(src_id=session_node, rel_type="DISCOVERED", dst_id=node_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "nodes": [
                {"id": n.node_id, "label": n.label, **n.props} for n in self.snapshot.nodes.values()
            ],
            "edges": [
                {"src": e.src_id, "rel": e.rel_type, "dst": e.dst_id, **e.props}
                for e in self.snapshot.edges
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)
