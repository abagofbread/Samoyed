from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from samoyed.graph.model import GraphSnapshot

RESOURCE_CONCEPTS = frozenset(
    {
        "DataStore",
        "SecretStore",
        "RuntimeBinding",
        "ManagementEndpoint",
        "RegistryStore",
        "ImageProvenance",
        "Workload",
        "EscapeSurface",
        "OrchestrationScope",
        "ScopeBoundary",
        "Entitlement",
        "Trust",
        "NetworkExposure",
    }
)


def _node_ref(snapshot: GraphSnapshot, node_id: str) -> str:
    node = snapshot.nodes.get(node_id)
    if not node:
        return node_id
    return (
        node.props.get("native_id")
        or node.props.get("arn")
        or node.props.get("display_name")
        or node_id
    )


def export_snapshot_to_iam_report(
    snapshot: GraphSnapshot,
    *,
    account_id: str,
    caller_arn: str | None = None,
    provider: str = "aws",
    scope_id: str | None = None,
    source: str = "samoyed-fixture-export",
    scenario: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert an existing graph snapshot to iam-report JSON (one-time fixture authoring)."""
    identities: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    seen_identity: set[str] = set()
    seen_resource: set[str] = set()

    for node in snapshot.nodes.values():
        if node.label == "CollectionSession":
            continue
        concept = node.props.get("concept_type", "")
        ref = _node_ref(snapshot, node.node_id)
        if concept == "Identity" or node.label == "Principal":
            if ref in seen_identity:
                continue
            seen_identity.add(ref)
            entry: dict[str, Any] = {
                "arn": node.props.get("arn") or (ref if ref.startswith("arn:") else None),
                "id": ref,
                "name": node.props.get("name") or node.props.get("display_name"),
                "kind": node.props.get("native_kind") or "Identity",
            }
            if node.props.get("is_caller"):
                entry["is_caller"] = True
            if node.props.get("is_scenario_start"):
                entry["is_scenario_start"] = True
            for key in ("display_name", "ou", "provider", "namespace", "notes"):
                if node.props.get(key) is not None:
                    entry[key] = node.props[key]
            identities.append({k: v for k, v in entry.items() if v is not None})
        elif concept in RESOURCE_CONCEPTS or node.label in {"Resource", "ComputeContext", "EscapeSurface"}:
            if ref in seen_resource:
                continue
            seen_resource.add(ref)
            entry = {
                "id": ref,
                "concept": concept or "DataStore",
                "type": node.props.get("resource_type") or node.props.get("native_kind") or "Resource",
                "name": node.props.get("name") or node.props.get("display_name") or node.props.get("bucket_name"),
            }
            if node.props.get("is_scenario_start"):
                entry["is_scenario_start"] = True
            for key in ("display_name", "bucket_name", "function_name", "namespace", "cluster", "ou", "severity"):
                if node.props.get(key) is not None:
                    entry[key] = node.props[key]
            resources.append({k: v for k, v in entry.items() if v is not None})

    grants: list[dict[str, Any]] = []
    for edge in snapshot.edges:
        src = snapshot.nodes.get(edge.src_id)
        dst = snapshot.nodes.get(edge.dst_id)
        if not src or not dst:
            continue
        if src.label == "CollectionSession" or dst.label == "CollectionSession":
            continue
        grant: dict[str, Any] = {
            "from": _node_ref(snapshot, edge.src_id),
            "to": _node_ref(snapshot, edge.dst_id),
            "rel": edge.rel_type,
        }
        for key in ("action", "confidence", "source", "via", "binding_type", "role", "severity", "execution_role_arn"):
            if edge.props.get(key) is not None:
                grant[key] = edge.props[key]
        grants.append(grant)

    doc: dict[str, Any] = {
        "account_id": account_id,
        "provider": provider,
        "source": source,
        "collected_via": "fixture-export",
        "identities": identities,
        "resources": resources,
        "grants": grants,
    }
    if caller_arn:
        doc["caller_arn"] = caller_arn
    if scope_id:
        doc["scope_id"] = scope_id
    if scenario:
        doc["scenario"] = scenario
    if extra_metadata:
        doc["metadata"] = extra_metadata
    if "collected_via" in (extra_metadata or {}):
        doc["collected_via"] = extra_metadata["collected_via"]
    return doc


def write_iam_report_fixture(path: Path, document: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path
