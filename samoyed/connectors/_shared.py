from __future__ import annotations

import json
import re
from typing import Any

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.attack.surface import enrich_attack_surface
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.cloud.providers import make_scope_id
from samoyed.graph.builder import GraphBuilder
from samoyed.ingest.concept_normalizer import ConceptNormalizer
from samoyed.network.enrich import enrich_network_reachability
from samoyed.network.model import NetworkInventory


def parse_json_payload(payload: bytes | str) -> Any:
    text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    text = text.strip()
    if text.startswith("scoutsuite_results"):
        text = re.sub(r"^scoutsuite_results\s*=\s*", "", text, count=1).rstrip(";")
    return json.loads(text)


def build_session_from_artifacts(
    artifacts: list,
    *,
    session_id: str,
    source: str,
    scope_id: str,
    scope_display: str,
    caller_arn: str | None,
    provider: CloudProvider = CloudProvider.AWS,
    account_id: str | None = None,
    network: NetworkInventory | dict[str, Any] | None = None,
    session_store: Any | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    if not artifacts:
        raise ValueError("No artifacts produced from import")

    builder = GraphBuilder(session_id)
    scope_props: dict[str, Any] = {
        "display_name": scope_display,
        "source": source,
        "account_id": account_id,
    }
    if provider == CloudProvider.AWS and account_id:
        scope_props["boundary_kind"] = "account"
    scope_node = builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id=scope_id,
        props=scope_props,
    )
    builder.link_session(scope_node)
    ConceptNormalizer().ingest(builder, artifacts)

    resolved_caller = caller_arn
    if resolved_caller:
        for node in builder.snapshot.nodes.values():
            native = node.props.get("native_id") or node.props.get("arn")
            if native == resolved_caller:
                node.props["is_caller"] = True

    attack_edges = apply_attack_analysis(builder, provider=provider)
    enrich_attack_surface(builder, provider=provider, session_store=session_store)
    inventory = (
        network
        if isinstance(network, NetworkInventory)
        else NetworkInventory.from_dict(network if isinstance(network, dict) else None)
    )
    network_stats = enrich_network_reachability(
        builder,
        inventory,
        session_store=session_store,
        inventory_source=inventory.source or source,
    )
    meta = {
        "source": source,
        "artifact_count": len(artifacts),
        "node_count": len(builder.snapshot.nodes) - 1,
        "attack_patterns_matched": len(attack_edges),
        "caller_arn": resolved_caller,
        "account_id": account_id,
        "network_enrichment": network_stats,
        "network_inventory": inventory.to_dict() if not inventory.is_empty() else None,
    }
    return builder, meta


def aws_scope(account_id: str) -> tuple[str, str]:
    scope_id = make_scope_id(CloudProvider.AWS, "account", account_id)
    return scope_id, f"AWS account {account_id}"
