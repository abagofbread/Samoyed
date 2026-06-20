from __future__ import annotations

from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import get_blast_radius


class LeakedCredentialScenario:
    name = "leaked-credential"
    target_concepts = ["AttackOutcome", "SecretStore", "DataStore", "Identity"]

    def run(self, graph: GraphSnapshot, start_node_id: str) -> list[PathResult]:
        return get_blast_radius(
            graph,
            start_node_id=start_node_id,
            target_concepts=self.target_concepts,
            max_depth=6,
        )
