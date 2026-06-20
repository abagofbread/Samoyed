from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.sessions import SessionRecord, SessionStore


STATIC_SUGGESTIONS: list[dict[str, Any]] = [
    {
        "id": "blast-radius",
        "title": "Blast radius from caller",
        "description": "All high-value targets reachable from the compromised identity",
        "mode": "blast",
        "start": "caller",
    },
    {
        "id": "paths-to-secrets",
        "title": "Paths to SecretStore",
        "description": "Find routes to secrets managers and K8s secrets",
        "mode": "paths",
        "start": "caller",
        "target_concept": "SecretStore",
        "max_depth": 6,
    },
    {
        "id": "paths-to-data",
        "title": "Paths to DataStore",
        "description": "Find routes to buckets, databases, and data volumes",
        "mode": "paths",
        "start": "caller",
        "target_concept": "DataStore",
        "max_depth": 6,
    },
    {
        "id": "paths-to-api",
        "title": "Paths to ManagementEndpoint",
        "description": "Find routes to control-plane APIs (K8s API, etc.)",
        "mode": "paths",
        "start": "caller",
        "target_concept": "ManagementEndpoint",
        "max_depth": 6,
    },
    {
        "id": "paths-to-identity",
        "title": "Paths to Identity (privilege escalation)",
        "description": "Find assume-role and identity pivot paths",
        "mode": "paths",
        "start": "caller",
        "target_concept": "Identity",
        "max_depth": 5,
    },
    {
        "id": "paths-to-escape",
        "title": "Paths to EscapeSurface",
        "description": "Container escape surfaces from current start",
        "mode": "paths",
        "start": "caller",
        "target_concept": "EscapeSurface",
        "max_depth": 5,
    },
    {
        "id": "paths-to-runtime",
        "title": "Paths to RuntimeBinding",
        "description": "Cloud IAM bindings via IRSA, instance profiles, nodes",
        "mode": "paths",
        "start": "caller",
        "target_concept": "RuntimeBinding",
        "max_depth": 6,
    },
    {
        "id": "short-path-secrets",
        "title": "Short paths to secrets (depth 3)",
        "description": "Quick wins — secrets within 3 hops",
        "mode": "paths",
        "start": "caller",
        "target_concept": "SecretStore",
        "max_depth": 3,
    },
    {
        "id": "caller-neighbors",
        "title": "1-hop neighbors of caller",
        "description": "Immediate adjacency from the start identity",
        "mode": "neighbors",
        "start": "caller",
    },
    {
        "id": "paths-to-workloads",
        "title": "Paths to Workload",
        "description": "Reach pods and compute workloads",
        "mode": "paths",
        "start": "caller",
        "target_concept": "Workload",
        "max_depth": 5,
    },
]


def _concepts_in_graph(session: SessionRecord) -> set[str]:
    return {
        n.props.get("concept_type", "")
        for n in session.snapshot.nodes.values()
        if n.props.get("concept_type")
    }


def _has_k8s(session: SessionRecord) -> bool:
    return session.provider.value == "kubernetes" or any(
        n.props.get("provider") == "kubernetes" for n in session.snapshot.nodes.values()
    )


def _has_aws(session: SessionRecord) -> bool:
    return session.provider.value == "aws" or any(
        "arn:aws" in str(n.props.get("native_id", "")) for n in session.snapshot.nodes.values()
    )


def _has_gcp(session: SessionRecord) -> bool:
    return session.provider.value == "gcp" or any(
        str(n.props.get("native_id", "")).startswith("gcp:") for n in session.snapshot.nodes.values()
    )


def _has_azure(session: SessionRecord) -> bool:
    return session.provider.value == "azure" or any(
        str(n.props.get("native_id", "")).startswith("azure:") for n in session.snapshot.nodes.values()
    )


def suggest_searches(store: SessionStore, session_id: str, *, limit: int = 10) -> list[dict[str, Any]]:
    session = store.get(session_id)
    if not session:
        return []

    concepts = _concepts_in_graph(session)
    ranked: list[dict[str, Any]] = []

    for suggestion in STATIC_SUGGESTIONS:
        target = suggestion.get("target_concept")
        if target and target not in concepts:
            continue
        ranked.append({**suggestion, "session_id": session_id})

    if _has_k8s(session):
        ranked.insert(
            2,
            {
                "id": "k8s-pod-escape",
                "title": "Pod escape (evil-pod)",
                "description": "Escape surfaces from a compromised workload pod",
                "mode": "scenario",
                "scenario": "pod-escape",
                "session_id": session_id,
            },
        )
        ranked.insert(
            3,
            {
                "id": "k8s-compromised-sa",
                "title": "Compromised service account",
                "description": "Blast radius from a leaked SA token",
                "mode": "scenario",
                "scenario": "compromised-sa",
                "session_id": session_id,
            },
        )

    if _has_aws(session):
        ranked.insert(
            1,
            {
                "id": "aws-leaked-cred",
                "title": "Leaked AWS credential",
                "description": "Classic IAM blast radius from caller",
                "mode": "scenario",
                "scenario": "leaked-credential",
                "session_id": session_id,
            },
        )

    if _has_gcp(session):
        ranked.insert(
            1,
            {
                "id": "gcp-leaked-sa",
                "title": "Leaked GCP service account",
                "description": "IAM blast radius from compromised SA",
                "mode": "scenario",
                "scenario": "leaked-credential",
                "session_id": session_id,
            },
        )

    if _has_azure(session):
        ranked.insert(
            1,
            {
                "id": "azure-leaked-sp",
                "title": "Leaked Azure service principal",
                "description": "RBAC blast radius from compromised SP",
                "mode": "scenario",
                "scenario": "leaked-credential",
                "session_id": session_id,
            },
        )

    # Dynamic: suggest path to each high-value concept present
    for concept in (
        ConceptType.SECRET_STORE.value,
        ConceptType.ESCAPE_SURFACE.value,
        ConceptType.MANAGEMENT_ENDPOINT.value,
    ):
        if concept in concepts and not any(s.get("target_concept") == concept for s in ranked):
            ranked.append(
                {
                    "id": f"dynamic-{concept.lower()}",
                    "title": f"Paths to {concept}",
                    "description": f"Graph contains {concept} nodes",
                    "mode": "paths",
                    "start": "caller",
                    "target_concept": concept,
                    "max_depth": 6,
                    "session_id": session_id,
                }
            )

    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in ranked:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        out.append(item)
        if len(out) >= limit:
            break
    return out
