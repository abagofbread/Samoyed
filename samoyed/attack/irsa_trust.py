"""Trust-validate IRSA ``PROJECTS_TO`` edges from OIDC role trust conditions."""

from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.credentials.k8s import sa_native_id
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.refs import resolve_node_ref
from samoyed.policy.irsa import (
    IrsaTrustMatch,
    is_oidc_provider_arn,
    parse_irsa_trust_document,
    sa_refs_for_match,
)


def enrich_irsa_trust(builder: GraphBuilder) -> dict[str, int]:
    """Upsert trust-validated SA→role PROJECTS_TO; demote annotation mismatches."""
    graph = builder.snapshot
    stats = {
        "irsa_trust_matches": 0,
        "irsa_projects_to": 0,
        "irsa_validated_stamped": 0,
        "irsa_annotation_unvalidated": 0,
        "irsa_sa_projected": 0,
        "irsa_oidc_assume_suppressed": 0,
    }

    inventored = _inventored_sas(graph)
    matches = _collect_trust_matches(graph)
    stats["irsa_trust_matches"] = len(matches)

    validated_pairs: set[tuple[str, str]] = set()  # (sa_node_id, role_node_id)

    for match in matches:
        role_id = _resolve_role(graph, match.role_arn)
        if not role_id:
            role_id = builder.add_concept_node(
                concept_type=ConceptType.IDENTITY,
                native_id=match.role_arn,
                props={
                    "native_kind": "Role",
                    "resource_type": "Role",
                    "arn": match.role_arn,
                    "name": match.role_arn.split("/")[-1],
                    "display_name": match.role_arn.split("/")[-1],
                    "projected": True,
                    "projected_reason": "irsa-trust",
                },
            )

        for ns, sa_name in sa_refs_for_match(match, inventored_sas=inventored):
            sa_native = sa_native_id(ns, sa_name)
            before = set(graph.nodes)
            sa_id = resolve_node_ref(graph, sa_native, prefer_concepts=("identity", "serviceaccount"))
            if not sa_id:
                sa_id = builder.add_concept_node(
                    concept_type=ConceptType.IDENTITY,
                    native_id=sa_native,
                    props={
                        "native_kind": "ServiceAccount",
                        "resource_type": "ServiceAccount",
                        "namespace": ns,
                        "name": sa_name,
                        "display_name": f"{ns}/{sa_name}",
                        "projected": True,
                        "projected_reason": "irsa-trust",
                        "source": "irsa-trust",
                    },
                )
            if sa_id not in before and graph.nodes[sa_id].props.get("projected_reason") == "irsa-trust":
                stats["irsa_sa_projected"] += 1

            props = enrichment_edge_props(
                source="irsa-trust",
                binding_type="IRSA",
                trust_validated=True,
                mechanism="oidc-sub",
                oidc_provider=match.oidc_provider,
                sub=match.sub_pattern,
                audience=match.audience,
                confidence="explicit",
            )
            if _upsert_projects_to(builder, graph, sa_id, role_id, props):
                stats["irsa_projects_to"] += 1
            else:
                stats["irsa_validated_stamped"] += 1
            validated_pairs.add((sa_id, role_id))

    # Annotation-only PROJECTS_TO that are not trust-validated → demote.
    for edge in graph.edges:
        if edge.rel_type != "PROJECTS_TO":
            continue
        if str(edge.props.get("binding_type") or "") != "IRSA":
            continue
        if edge.props.get("trust_validated") is True:
            continue
        pair = (edge.src_id, edge.dst_id)
        if pair in validated_pairs:
            edge.props["trust_validated"] = True
            edge.props.setdefault("mechanism", "oidc-sub")
            stats["irsa_validated_stamped"] += 1
            continue
        # Annotation without matching trust
        if edge.props.get("annotation") or edge.props.get("source") != "irsa-trust":
            edge.props["trust_validated"] = False
            edge.props.setdefault("confidence", "inferred")
            stats["irsa_annotation_unvalidated"] += 1

    stats["irsa_oidc_assume_suppressed"] = _suppress_oidc_can_assume(graph)
    return stats


def _collect_trust_matches(graph: GraphSnapshot) -> list[IrsaTrustMatch]:
    matches: list[IrsaTrustMatch] = []
    seen: set[tuple[str, str, str, str | None]] = set()

    for node in graph.nodes.values():
        role_arn = str(node.props.get("role_arn") or node.props.get("arn") or "")
        trust = (
            node.props.get("trust_doc")
            or node.props.get("assume_role_policy")
            or node.props.get("assume_role_policy_document")
            or node.props.get("trust_policy")
            or node.props.get("AssumeRolePolicyDocument")
        )
        if not trust:
            continue
        # Trust artifacts carry role_arn; Role identities use arn.
        if not role_arn and node.props.get("native_kind") == "Role":
            role_arn = str(node.props.get("native_id") or "")
        if not role_arn:
            continue
        if ":role/" not in role_arn and node.props.get("native_kind") not in {None, "Role", "Trust"}:
            # Skip non-role trust carriers without a clear role_arn
            if "role_arn" not in node.props:
                continue
        for match in parse_irsa_trust_document(trust, role_arn=role_arn):
            key = (match.role_arn, match.oidc_provider, match.namespace, match.sa_name)
            if key in seen:
                continue
            seen.add(key)
            matches.append(match)

    return matches


def _inventored_sas(graph: GraphSnapshot) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for node in graph.nodes.values():
        native = str(node.props.get("native_id") or "")
        if not native.startswith("kubernetes:serviceaccount:"):
            if str(node.props.get("native_kind") or "") != "ServiceAccount":
                continue
            ns = str(node.props.get("namespace") or "default")
            name = str(node.props.get("name") or node.props.get("display_name") or "")
            if name:
                out.append((ns, name.split("/")[-1]))
            continue
        parts = native.split(":")
        # kubernetes:serviceaccount:ns:name
        if len(parts) >= 4:
            out.append((parts[2], parts[3]))
    return out


def _resolve_role(graph: GraphSnapshot, role_arn: str) -> str | None:
    hit = resolve_node_ref(graph, role_arn, prefer_concepts=("identity", "role"))
    if hit:
        return hit
    name = role_arn.split("/")[-1] if "/" in role_arn else role_arn
    return resolve_node_ref(graph, name, prefer_concepts=("identity", "role"))


def _upsert_projects_to(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    sa_id: str,
    role_id: str,
    props: dict[str, Any],
) -> bool:
    for edge in graph.edges:
        if edge.src_id == sa_id and edge.dst_id == role_id and edge.rel_type == "PROJECTS_TO":
            edge.props.update(props)
            return False
    builder.add_edge(src_id=sa_id, rel_type="PROJECTS_TO", dst_id=role_id, props=props)
    return True


def _suppress_oidc_can_assume(graph: GraphSnapshot) -> int:
    """Mark bare OIDC-provider → role CAN_ASSUME_ROLE as non-traversable."""
    n = 0
    for edge in graph.edges:
        if edge.rel_type != "CAN_ASSUME_ROLE":
            continue
        src = graph.nodes.get(edge.src_id)
        if not src:
            continue
        native = str(src.props.get("native_id") or src.props.get("arn") or "")
        if not is_oidc_provider_arn(native) and not is_oidc_provider_arn(edge.src_id):
            # Also check principal prop on edge
            if not is_oidc_provider_arn(str(edge.props.get("principal") or "")):
                continue
        if edge.props.get("non_traversable"):
            continue
        edge.props["non_traversable"] = True
        edge.props.setdefault("reason", "oidc-provider-not-principal")
        n += 1
    return n
