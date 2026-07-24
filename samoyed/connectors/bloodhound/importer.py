"""Import BloodHound / AzureHound / SharpHound JSON into a Samoyed session."""

from __future__ import annotations

from typing import Any

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.cloud.providers import make_scope_id
from samoyed.connectors._shared import build_session_from_artifacts, parse_json_payload
from samoyed.connectors.bloodhound.mapping import (
    IGNORED_EDGE_KINDS,
    concept_for_node,
    map_bh_edge,
    native_id_for_node,
    node_directory,
    normalize_bh_kind,
    primary_kind,
)
from samoyed.connectors.bloodhound.parse import BHEdge, BHNode, ParsedBloodHound, parse_bloodhound_payload
from samoyed.graph.builder import GraphBuilder

_CONCEPT_ENUM = {
    "Identity": ConceptType.IDENTITY,
    "Workload": ConceptType.WORKLOAD,
    "SecretStore": ConceptType.SECRET_STORE,
    "DataStore": ConceptType.DATA_STORE,
    "ScopeBoundary": ConceptType.SCOPE_BOUNDARY,
    "RuntimeBinding": ConceptType.RUNTIME_BINDING,
    "AttackOutcome": ConceptType.ATTACK_OUTCOME,
}


def import_bloodhound(
    payload: bytes | str | dict[str, Any],
    *,
    session_id: str,
    caller_arn: str | None = None,
    session_store: Any | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    if isinstance(payload, dict):
        data = payload
    else:
        data = parse_json_payload(payload)

    parsed = parse_bloodhound_payload(data)
    if not parsed.nodes and not parsed.edges:
        raise ValueError("No BloodHound nodes or edges found in payload")

    # Ensure edge endpoints exist as nodes.
    _ensure_endpoint_nodes(parsed)

    tenant_id = str(parsed.meta.get("tenant_id") or _guess_tenant(parsed) or "unknown")
    domain = str(parsed.meta.get("domain") or "contoso.local")
    has_entra = _has_entra(parsed)

    if has_entra:
        scope_id = make_scope_id(CloudProvider.AZURE, "tenant", tenant_id)
        scope_display = f"Entra tenant {tenant_id}"
        provider = CloudProvider.AZURE
    else:
        scope_id = f"ad:domain:{domain}"
        scope_display = f"AD domain {domain}"
        provider = CloudProvider.AZURE  # directory graph; no dedicated AD provider

    id_map = _build_native_id_map(parsed)
    artifacts = _artifacts_from_parsed(
        parsed,
        id_map=id_map,
        scope_id=scope_id,
        provider=provider,
        tenant_id=tenant_id,
    )

    resolved_caller = caller_arn or _default_caller(artifacts, parsed, id_map)
    builder, meta = build_session_from_artifacts(
        artifacts,
        session_id=session_id,
        source="bloodhound",
        scope_id=scope_id,
        scope_display=scope_display,
        caller_arn=resolved_caller,
        provider=provider,
        session_store=session_store,
    )
    meta["provider"] = provider.value
    meta["tenant_id"] = tenant_id
    meta["domain"] = domain
    meta["bh_format"] = parsed.meta.get("format")
    meta["bh_node_count"] = len(parsed.nodes)
    meta["bh_edge_count"] = len(parsed.edges)
    meta["ignored_edge_kinds"] = sorted(IGNORED_EDGE_KINDS)
    return builder, meta


def _ensure_endpoint_nodes(parsed: ParsedBloodHound) -> None:
    known = {n.object_id for n in parsed.nodes}
    for edge in parsed.edges:
        for endpoint, hint_kinds in ((edge.start, ["Base"]), (edge.end, ["Base"])):
            if endpoint and endpoint not in known:
                kinds = _infer_kinds_from_edge(edge, endpoint)
                parsed.nodes.append(BHNode(object_id=endpoint, kinds=kinds or hint_kinds, properties={}))
                known.add(endpoint)


def _infer_kinds_from_edge(edge: BHEdge, endpoint: str) -> list[str]:
    kind = normalize_bh_kind(edge.kind)
    if kind.startswith("AZ") or kind == "SyncedToADUser":
        if endpoint == edge.end and kind in {"AZAddSecret", "AZMGAddSecret", "AZOwns"}:
            return ["AZServicePrincipal"]
        if endpoint.startswith("S-1-"):
            return ["User"]
        return ["AZUser"]
    if kind == "HasSession":
        return ["Computer"] if endpoint == edge.start else ["User"]
    if kind in {"AdminTo", "CanRDP", "CanPSRemote"}:
        return ["User"] if endpoint == edge.start else ["Computer"]
    if kind in {"MemberOf", "AZMemberOf"}:
        return ["User"] if endpoint == edge.start else ["Group"]
    if endpoint.startswith("S-1-"):
        return ["User"]
    return ["Base"]


def _build_native_id_map(parsed: ParsedBloodHound) -> dict[str, str]:
    id_map: dict[str, str] = {}
    for node in parsed.nodes:
        nid = native_id_for_node(node.object_id, node.kinds, node.properties)
        id_map[node.object_id] = nid
        # Also index by name for OpenGraph match_by=name (best-effort).
        name = node.properties.get("name") or node.properties.get("displayname")
        if name and str(name) not in id_map:
            id_map[str(name)] = nid
    return id_map


def _artifacts_from_parsed(
    parsed: ParsedBloodHound,
    *,
    id_map: dict[str, str],
    scope_id: str,
    provider: CloudProvider,
    tenant_id: str,
) -> list[ConceptArtifact]:
    edges_by_src: dict[str, list[ConceptEdge]] = {nid: [] for nid in id_map.values()}
    kind_by_oid = {n.object_id: n.kinds for n in parsed.nodes}
    props_by_oid = {n.object_id: n.properties for n in parsed.nodes}
    stats_ignored = 0

    for edge in parsed.edges:
        mapped = map_bh_edge(
            edge.kind,
            src_kinds=kind_by_oid.get(edge.start, []),
            dst_kinds=kind_by_oid.get(edge.end, []),
        )
        if mapped is None:
            stats_ignored += 1
            continue
        for spec in mapped:
            start_oid, end_oid = edge.start, edge.end
            if spec.reverse:
                start_oid, end_oid = end_oid, start_oid
            src_native = id_map.get(start_oid) or id_map.get(str(start_oid))
            dst_native = id_map.get(end_oid) or id_map.get(str(end_oid))
            if not src_native or not dst_native:
                continue
            target_concept = None
            if spec.target_concept:
                target_concept = _CONCEPT_ENUM.get(spec.target_concept)
            elif end_oid in kind_by_oid:
                target_concept = _CONCEPT_ENUM.get(concept_for_node(kind_by_oid[end_oid], props_by_oid.get(end_oid)))
            props = {
                **spec.props,
                **(edge.properties or {}),
                "source": "bloodhound",
            }
            edges_by_src.setdefault(src_native, []).append(
                ConceptEdge(
                    rel_type=spec.rel_type,
                    target_native_id=dst_native,
                    target_concept_type=target_concept,
                    props=props,
                    confidence=ConfidenceType.EXPLICIT,
                )
            )

    artifacts: list[ConceptArtifact] = []
    seen_native: set[str] = set()
    for node in parsed.nodes:
        native_id = id_map[node.object_id]
        if native_id in seen_native:
            continue
        seen_native.add(native_id)
        concept_name = concept_for_node(node.kinds, node.properties)
        concept = _CONCEPT_ENUM.get(concept_name, ConceptType.IDENTITY)
        directory = node_directory(node.kinds, node.properties)
        display = (
            node.properties.get("displayname")
            or node.properties.get("displayName")
            or node.properties.get("name")
            or node.object_id
        )
        props: dict[str, Any] = {
            "native_kind": primary_kind(node.kinds),
            "name": node.properties.get("name") or display,
            "display_name": display,
            "directory": directory,
            "bh_object_id": node.object_id,
            "bh_kinds": list(node.kinds),
            "source": "bloodhound",
            "tenant_id": tenant_id if directory == "entra" else None,
        }
        props = {k: v for k, v in props.items() if v is not None}
        if concept == ConceptType.WORKLOAD:
            props.setdefault("pivot_surface", "host")
            if _node_has_session(parsed, node.object_id):
                props["native_kind"] = "CompromisedHost"
                props["is_scenario_start"] = True
        if concept == ConceptType.SECRET_STORE:
            props.setdefault("resource_type", "KeyVault" if "secret" not in native_id else "KeyVaultSecret")

        node_provider = CloudProvider.AZURE if directory == "entra" else provider
        artifacts.append(
            ConceptArtifact(
                concept_type=concept,
                provider=node_provider,
                native_id=native_id,
                scope_id=scope_id,
                properties=props,
                evidence=Evidence("bloodhound", {"object_id": node.object_id, "kinds": node.kinds}),
                edges=list(edges_by_src.get(native_id, [])),
            )
        )

    # Orphan edges whose src was never materialized as a primary node kind.
    for native_id, edges in edges_by_src.items():
        if native_id in seen_native or not edges:
            continue
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=provider,
                native_id=native_id,
                scope_id=scope_id,
                properties={"native_kind": "Identity", "source": "bloodhound", "display_name": native_id},
                evidence=Evidence("bloodhound:orphan", {"native_id": native_id}),
                edges=edges,
            )
        )

    parsed.meta["ignored_edge_count"] = stats_ignored
    return artifacts


def _node_has_session(parsed: ParsedBloodHound, object_id: str) -> bool:
    return any(
        normalize_bh_kind(e.kind) == "HasSession" and e.start == object_id for e in parsed.edges
    )


def _has_entra(parsed: ParsedBloodHound) -> bool:
    if parsed.meta.get("tenant_id"):
        return True
    for node in parsed.nodes:
        if any(str(k).upper().startswith("AZ") for k in node.kinds):
            return True
        if str(node.object_id).startswith("azure:"):
            return True
    for edge in parsed.edges:
        if normalize_bh_kind(edge.kind).startswith("AZ") or normalize_bh_kind(edge.kind) == "SyncedToADUser":
            return True
    return False


def _guess_tenant(parsed: ParsedBloodHound) -> str | None:
    for node in parsed.nodes:
        for key in ("tenantid", "tenantId", "tenant-id"):
            if node.properties.get(key):
                return str(node.properties[key])
    return None


def _default_caller(
    artifacts: list[ConceptArtifact],
    parsed: ParsedBloodHound,
    id_map: dict[str, str],
) -> str | None:
    for art in artifacts:
        if art.properties.get("is_scenario_start"):
            return art.native_id
    # Prefer a user that AdminTo's a computer (attacker foothold).
    for edge in parsed.edges:
        if normalize_bh_kind(edge.kind) in {"AdminTo", "CanRDP", "CanPSRemote"}:
            return id_map.get(edge.start)
    for art in artifacts:
        if art.concept_type == ConceptType.IDENTITY and art.native_id.startswith(("ad:user:", "azure:user:")):
            return art.native_id
    return artifacts[0].native_id if artifacts else None
