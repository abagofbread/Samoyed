"""Graph query backends: in-memory snapshot vs Neo4j Cypher (Phase 3)."""

from __future__ import annotations

import os
from typing import Literal

from samoyed.graph.neo4j_store import neo4j_configured

BackendName = Literal["auto", "memory", "neo4j"]


def resolve_graph_backend(explicit: str | None = None) -> Literal["memory", "neo4j"]:
    """Pick the path/blast backend.

    ``SAMOYED_GRAPH_BACKEND``: ``auto`` (default) | ``memory`` | ``neo4j``.
    ``auto`` uses Neo4j when ``NEO4J_URI`` is set.
    """
    raw = (explicit or os.environ.get("SAMOYED_GRAPH_BACKEND") or "auto").strip().lower()
    if raw == "memory":
        return "memory"
    if raw == "neo4j":
        if not neo4j_configured():
            raise RuntimeError("SAMOYED_GRAPH_BACKEND=neo4j requires NEO4J_URI")
        return "neo4j"
    # auto
    return "neo4j" if neo4j_configured() else "memory"
