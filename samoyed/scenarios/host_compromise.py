from __future__ import annotations

from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import find_attack_paths, get_blast_radius


class HostCompromiseScenario:
    name = "host-compromise"
    target_concepts = ["AttackOutcome", "Identity", "SecretStore", "DataStore"]

    def run(self, graph: GraphSnapshot, start_node_id: str) -> list[PathResult]:
        paths = get_blast_radius(
            graph,
            start_node_id=start_node_id,
            max_depth=8,
        )
        # Include paths through stolen cloud identities (LOGGED_IN_AS / STORES_CREDS_FOR)
        for dst_id, rel, _props in graph.adjacency.get(start_node_id, []):
            if rel not in {"LOGGED_IN_AS", "STORES_CREDS_FOR"}:
                continue
            paths.extend(
                get_blast_radius(
                    graph,
                    start_node_id=dst_id,
                    max_depth=6,
                )
            )
            paths.extend(
                find_attack_paths(
                    graph,
                    start_node_id=dst_id,
                    target_concept="AttackOutcome",
                    max_depth=6,
                    max_paths=5,
                )
            )
        seen: set[str] = set()
        unique: list[PathResult] = []
        for path in sorted(paths, key=lambda p: p.score, reverse=True):
            if path.path_id not in seen:
                seen.add(path.path_id)
                unique.append(path)
        return unique[:15]
