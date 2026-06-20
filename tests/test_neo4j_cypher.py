from __future__ import annotations

import pytest

from samoyed.graph.neo4j_store import run_readonly_cypher


def test_run_readonly_cypher_rejects_writes(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7687")
    with pytest.raises(ValueError, match="Write operations"):
        run_readonly_cypher("CREATE (n:Test {id: 1}) RETURN n")
