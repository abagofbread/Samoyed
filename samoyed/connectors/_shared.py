from __future__ import annotations

import json
import re
from typing import Any

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.cloud.providers import make_scope_id
from samoyed.graph.builder import GraphBuilder
from samoyed.ingest.concept_normalizer import ConceptNormalizer


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
) -> tuple[GraphBuilder, dict[str, Any]]:
    if not artifacts:
        raise ValueError("No artifacts produced from import")

    builder = GraphBuilder(session_id)
    scope_node = builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id=scope_id,
        props={
            "display_name": scope_display,
            "source": source,
            "account_id": account_id,
        },
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
    meta = {
        "source": source,
        "artifact_count": len(artifacts),
        "node_count": len(builder.snapshot.nodes) - 1,
        "attack_patterns_matched": len(attack_edges),
        "caller_arn": resolved_caller,
        "account_id": account_id,
    }
    return builder, meta


def aws_scope(account_id: str) -> tuple[str, str]:
    scope_id = make_scope_id(CloudProvider.AWS, "account", account_id)
    return scope_id, f"AWS account {account_id}"
