from __future__ import annotations

from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import find_attack_paths, get_blast_radius


class CompromisedSaScenario:
    name = "compromised-sa"
    target_concepts = ["SecretStore", "ManagementEndpoint", "Identity"]

    def run(self, graph: GraphSnapshot, start_node_id: str) -> list[PathResult]:
        return get_blast_radius(
            graph,
            start_node_id=start_node_id,
            max_depth=6,
        )


class PodEscapeScenario:
    name = "pod-escape"
    target_concepts = ["RuntimeBinding", "SecretStore", "Identity"]

    def run(self, graph: GraphSnapshot, start_node_id: str) -> list[PathResult]:
        paths: list[PathResult] = []
        seen: set[str] = set()

        for concept in self.target_concepts:
            for path in find_attack_paths(
                graph,
                start_node_id=start_node_id,
                target_concept=concept,
                max_depth=6,
                max_paths=5,
            ):
                if path.path_id not in seen:
                    seen.add(path.path_id)
                    paths.append(path)

        paths.sort(key=lambda p: p.score, reverse=True)
        return paths
