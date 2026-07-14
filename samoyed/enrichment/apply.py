from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.enrichment.catalog import get_material_kind
from samoyed.enrichment.report import material_native_id, parse_enrichment_report
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props, mark_enrichment_edges
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.refs import resolve_node_ref
from samoyed.graph.native_ids import infer_concept_type


def apply_enrichment_report(
    builder: GraphBuilder,
    payload: bytes | str | dict[str, Any],
    *,
    default_target_node_id: str | None = None,
) -> dict[str, Any]:
    """
    Merge collector output onto an existing graph session.

    Each binding attaches predefined material kinds to a host node and extends
    blast radius via HAS_MATERIAL / UNLOCKS enrichment edges.
    """
    report = parse_enrichment_report(payload)
    graph = builder.snapshot
    stats = {
        "bindings_applied": 0,
        "materials_applied": 0,
        "materials_removed": 0,
        "edges_added": 0,
        "edges_removed": 0,
        "hosts_updated": [],
        "unresolved_bindings": [],
        "skipped_materials": [],
    }

    for index, binding in enumerate(report.get("bindings") or []):
        host_id = _resolve_binding_target(graph, binding, default_target_node_id=default_target_node_id)
        if not host_id:
            stats["unresolved_bindings"].append(
                {
                    "index": index,
                    "target_ref": binding.get("target_ref") or binding.get("target_node_id"),
                }
            )
            continue

        host = graph.nodes[host_id]
        host_native = str(host.props.get("native_id") or host_id)
        materials = binding.get("materials") or []
        if not materials:
            continue

        cleared = _clear_host_collector_enrichment(graph, host_id)
        stats["materials_removed"] += cleared["materials_removed"]
        stats["edges_removed"] += cleared["edges_removed"]
        if host_id not in stats["hosts_updated"]:
            stats["hosts_updated"].append(host_id)

        applied_kinds: list[str] = []

        for material in materials:
            kind = str(material.get("kind") or "")
            try:
                spec = get_material_kind(kind)
            except ValueError as exc:
                stats["skipped_materials"].append({"kind": kind, "error": str(exc)})
                continue

            locator = str(material.get("locator") or kind)
            if kind == "none_observed":
                _merge_host_enrichment_summary(host, kind=kind, locator=locator, report=report)
                applied_kinds.append(kind)
                stats["materials_applied"] += 1
                continue

            resolves_to = material.get("resolves_to")
            if spec.requires_target and not resolves_to:
                stats["skipped_materials"].append(
                    {"kind": kind, "locator": locator, "error": "resolves_to required for this kind"}
                )
                continue

            mat_native = material.get("id") or material_native_id(host_native, kind, locator)
            mat_id = builder.add_concept_node(
                concept_type=ConceptType.SECRET_STORE,
                native_id=mat_native,
                props={
                    "native_kind": "PivotMaterial",
                    "material_kind": kind,
                    "display_name": f"{spec.display_name}: {locator}",
                    "locator": locator,
                    "extends_blast_to": spec.extends_blast_to,
                    "collector": report.get("collector"),
                    "collector_mode": report.get("collector_mode"),
                    "confidence": material.get("confidence") or "explicit",
                    "evidence": material.get("evidence") or {},
                    "source": "collector-enrichment",
                },
            )
            stats["edges_added"] += int(
                _add_edge(
                    builder,
                    graph,
                    host_id,
                    spec.host_rel,
                    mat_id,
                    enrichment_edge_props(
                        source="collector",
                        material_kind=kind,
                        locator=locator,
                        collector=report.get("collector"),
                        confidence=material.get("confidence") or "explicit",
                    ),
                )
            )

            if resolves_to:
                target_concept = infer_concept_type(str(resolves_to)) or ConceptType.IDENTITY
                target_id = builder.add_concept_node(
                    concept_type=target_concept,
                    native_id=str(resolves_to),
                    props={"display_name": str(resolves_to), "source": "collector-enrichment"},
                )
                stats["edges_added"] += int(
                    _add_edge(
                        builder,
                        graph,
                        mat_id,
                        spec.unlock_rel,
                        target_id,
                        enrichment_edge_props(
                            source="collector",
                            material_kind=kind,
                            locator=locator,
                            resolves_to=resolves_to,
                            collector=report.get("collector"),
                            confidence=material.get("confidence") or "explicit",
                        ),
                    )
                )

            applied_kinds.append(kind)
            stats["materials_applied"] += 1

        if applied_kinds:
            _merge_host_enrichment_summary(
                host,
                kind=applied_kinds[-1],
                locator=materials[-1].get("locator") if materials else "",
                report=report,
                material_kinds=applied_kinds,
                material_count=len(applied_kinds),
            )
            stats["bindings_applied"] += 1

    stats["enrichment_edges_marked"] = mark_enrichment_edges(builder.snapshot)
    return stats


def _resolve_binding_target(
    graph: GraphSnapshot,
    binding: dict[str, Any],
    *,
    default_target_node_id: str | None,
) -> str | None:
    if binding.get("target_node_id"):
        node_id = str(binding["target_node_id"])
        return node_id if node_id in graph.nodes else None
    target_ref = binding.get("target_ref")
    if target_ref:
        return resolve_node_ref(graph, str(target_ref))
    if default_target_node_id and default_target_node_id in graph.nodes:
        return default_target_node_id
    return None


def _clear_host_collector_enrichment(graph: GraphSnapshot, host_id: str) -> dict[str, int]:
    """
    Drop prior collector-sourced pivot materials for one host only.

    IAM enum edges and other hosts are untouched — subsequent enrichment uploads
    replace the affected node's collector state, not the whole session.
    """
    result = {"materials_removed": 0, "edges_removed": 0}
    material_ids: list[str] = []
    for edge in graph.edges:
        if edge.src_id != host_id or edge.rel_type != "HAS_MATERIAL":
            continue
        if edge.props.get("source") != "collector":
            continue
        material = graph.nodes.get(edge.dst_id)
        if material and material.props.get("source") == "collector-enrichment":
            material_ids.append(edge.dst_id)

    for material_id in dict.fromkeys(material_ids):
        edge_count = sum(
            1 for edge in graph.edges if edge.src_id == material_id or edge.dst_id == material_id
        )
        if graph.remove_node(material_id):
            result["materials_removed"] += 1
            result["edges_removed"] += edge_count

    host = graph.nodes.get(host_id)
    if host:
        for key in [prop for prop in host.props if prop.startswith("enrichment_")]:
            del host.props[key]
    return result


def _merge_host_enrichment_summary(
    host: Any,
    *,
    kind: str,
    locator: str,
    report: dict[str, Any],
    material_kinds: list[str] | None = None,
    material_count: int | None = None,
) -> None:
    kinds = material_kinds or [kind]
    host.props["enrichment_collector"] = report.get("collector")
    host.props["enrichment_collector_mode"] = report.get("collector_mode")
    host.props["enrichment_collected_at"] = report.get("collected_at")
    host.props["enrichment_material_kinds"] = kinds
    host.props["enrichment_material_count"] = material_count if material_count is not None else len(kinds)
    host.props["enrichment_last_locator"] = locator
    if kind == "none_observed":
        host.props["enrichment_status"] = "clean"
    else:
        host.props["enrichment_status"] = "material_found"


def _add_edge(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    src_id: str,
    rel_type: str,
    dst_id: str,
    props: dict[str, Any],
) -> bool:
    for dst, rel, _ in graph.adjacency.get(src_id, []):
        if dst == dst_id and rel == rel_type:
            return False
    builder.add_edge(src_id=src_id, rel_type=rel_type, dst_id=dst_id, props=props)
    return True
