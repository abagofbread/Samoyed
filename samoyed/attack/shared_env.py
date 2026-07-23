"""Mark DataStores/registries consumed by multiple environments (prod+dev bleed)."""

from __future__ import annotations

from typing import Any

from samoyed.enumerators.aws.tags import environment_from_props
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import MARKING_HIGH_VALUE, apply_marking
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.resource_scope import CONSUMER_RELS

_STORE_CONCEPTS = frozenset({"DataStore", "SecretStore", "RegistryStore"})


def enrich_shared_environments(builder: GraphBuilder) -> dict[str, int]:
    """Flag resources with consumers in ≥2 environments; soft-mark as high value."""
    graph = builder.snapshot
    fan: dict[str, set[str]] = {}
    consumer_envs: dict[str, list[dict[str, str]]] = {}

    for edge in graph.edges:
        if edge.rel_type not in CONSUMER_RELS:
            continue
        dst = graph.nodes.get(edge.dst_id)
        if not dst:
            continue
        if dst.props.get("concept_type") not in _STORE_CONCEPTS and not _resource_type_store(dst.props):
            continue
        src = graph.nodes.get(edge.src_id)
        env = environment_from_props(src.props) if src else None
        if not env:
            env = environment_from_props(edge.props)
        if not env:
            continue
        fan.setdefault(edge.dst_id, set()).add(env)
        consumer_envs.setdefault(edge.dst_id, []).append(
            {
                "consumer_id": edge.src_id,
                "environment": env,
                "rel": edge.rel_type,
            }
        )

    for edge in graph.edges:
        if edge.rel_type not in {"WRITES", "CONTROLS"}:
            continue
        dst = graph.nodes.get(edge.dst_id)
        if not dst or (
            dst.props.get("concept_type") not in _STORE_CONCEPTS and not _resource_type_store(dst.props)
        ):
            continue
        src = graph.nodes.get(edge.src_id)
        env = environment_from_props(src.props) if src else None
        if env:
            fan.setdefault(edge.dst_id, set()).add(env)

    marked = 0
    shared = 0
    for node_id, envs in fan.items():
        if len(envs) < 2:
            continue
        node = graph.nodes.get(node_id)
        if not node:
            continue
        shared += 1
        env_list = sorted(envs)
        node.props["shared_across_envs"] = True
        node.props["shared_environments"] = env_list
        node.props["cross_env_consumers"] = consumer_envs.get(node_id, [])
        node.props["shared_env_reason"] = (
            f"Resource used across environments: {', '.join(env_list)}"
        )
        if not node.props.get(MARKING_HIGH_VALUE):
            apply_marking(node.props, high_value=True, source="shared-across-envs")
            if not node.props.get("high_value_kind"):
                node.props["high_value_kind"] = "shared-across-envs"
                node.props["high_value_reason"] = node.props["shared_env_reason"]
            marked += 1
        else:
            node.props.setdefault("high_value_signals", [])
            signals = node.props["high_value_signals"]
            if isinstance(signals, list) and "shared-across-envs" not in signals:
                signals.append("shared-across-envs")

    return {
        "shared_across_envs": shared,
        "shared_env_high_value_marked": marked,
    }


def list_resource_consumers(graph: GraphSnapshot, resource_node_id: str) -> dict[str, Any]:
    """Who READS/USES/PULLS/DEPENDS_ON this resource (for UI shared-blast queries)."""
    node = graph.nodes.get(resource_node_id)
    if not node:
        return {"resource_node_id": resource_node_id, "error": "not found", "consumers": []}
    consumers: list[dict[str, Any]] = []
    for edge in graph.edges:
        if edge.dst_id != resource_node_id or edge.rel_type not in CONSUMER_RELS:
            continue
        src = graph.nodes.get(edge.src_id)
        props = src.props if src else {}
        consumers.append(
            {
                "node_id": edge.src_id,
                "rel": edge.rel_type,
                "environment": environment_from_props(props) or environment_from_props(edge.props),
                "display": props.get("display_name") or props.get("native_id") or edge.src_id,
                "concept_type": props.get("concept_type"),
                "resource_type": props.get("resource_type"),
            }
        )
    producers: list[dict[str, Any]] = []
    for edge in graph.edges:
        if edge.dst_id != resource_node_id or edge.rel_type not in {"WRITES", "CONTROLS", "DELETES"}:
            continue
        src = graph.nodes.get(edge.src_id)
        props = src.props if src else {}
        producers.append(
            {
                "node_id": edge.src_id,
                "rel": edge.rel_type,
                "environment": environment_from_props(props),
                "display": props.get("display_name") or props.get("native_id") or edge.src_id,
            }
        )
    envs = sorted(
        {
            *(c["environment"] for c in consumers if c.get("environment")),
            *(p["environment"] for p in producers if p.get("environment")),
        }
    )
    return {
        "resource_node_id": resource_node_id,
        "display": node.props.get("display_name") or node.props.get("native_id") or resource_node_id,
        "shared_across_envs": bool(node.props.get("shared_across_envs")) or len(envs) >= 2,
        "environments": envs or node.props.get("shared_environments") or [],
        "consumers": consumers,
        "producers": producers,
    }


def _resource_type_store(props: dict[str, Any]) -> bool:
    rtype = props.get("resource_type") or ""
    return rtype in {
        "S3Bucket",
        "ECRRepository",
        "Secret",
        "SSMParameter",
        "KMSKey",
        "KubernetesSecret",
    }
