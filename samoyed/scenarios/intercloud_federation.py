from __future__ import annotations

from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import find_attack_paths


class IntercloudFederationScenario:
    """Prefer caller blast-radius paths that cross an AWS/GCP identity boundary."""

    name = "intercloud-federation"

    def run(self, graph: GraphSnapshot, start_node_id: str) -> list[PathResult]:
        candidates = find_attack_paths(graph, start_node_id=start_node_id, max_depth=8)
        crossing = [path for path in candidates if _crosses_providers(graph, path)]
        return crossing or candidates


def _crosses_providers(graph: GraphSnapshot, path: PathResult) -> bool:
    providers: set[str] = set()
    for node_id in path.node_ids:
        node = graph.nodes.get(node_id)
        if not node:
            continue
        provider = str(node.props.get("provider") or "")
        native = str(node.props.get("native_id") or "")
        if provider in {"aws", "gcp"}:
            providers.add(provider)
        elif native.startswith("arn:aws"):
            providers.add("aws")
        elif native.startswith(("gcp:", "GCSBucket:", "GCPSecret:")):
            providers.add("gcp")
    return providers == {"aws", "gcp"}
