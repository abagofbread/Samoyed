"""Import collector enrichment onto a session graph.

Enrichment is an **import**: materials upsert by stable id, hosts and unlock
targets are resolved with the same fuzzy ref logic as marks/paths, and
re-importing the same report replaces prior collector materials instead of
duplicating them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.collectors.sa_token import enrich_sa_token_material
from samoyed.enrichment.catalog import get_material_kind
from samoyed.enrichment.impact import wire_credential_impact
from samoyed.enrichment.inventory import preferred_enrichment_host, project_declared_inventory
from samoyed.enrichment.labels import (
    enrich_assess_item,
    is_weak_label,
    material_detail_props,
)
from samoyed.enrichment.redact import redact_evidence, redact_secret_text
from samoyed.enrichment.report import material_native_id, parse_enrichment_report
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props, mark_enrichment_edges
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.refs import prefer_concepts_for_material, resolve_node_ref
from samoyed.graph.native_ids import infer_concept_type

_HOST_CONCEPTS = frozenset({"RuntimeBinding", "Workload"})
_HOST_PREFER = (
    "runtimebinding",
    "workload",
    "ec2instance",
    "ecscontainer",
    "lambdafunction",
    "compromisedhost",
    "host",
)
_UNBOUND_REFS = frozenset({"", "unbound", "none", "null"})


def apply_enrichment_report(
    builder: GraphBuilder,
    payload: bytes | str | dict[str, Any],
    *,
    default_target_node_id: str | None = None,
) -> dict[str, Any]:
    """
    Merge collector output onto an existing graph session.

    - Hosts and unlock targets are fuzzy-resolved automatically.
    - Materials use host-independent stable ids so repeated imports upsert.
    - Prior collector materials for the same import scope are replaced.
    """
    report = parse_enrichment_report(payload)
    graph = builder.snapshot
    stats: dict[str, Any] = {
        "bindings_applied": 0,
        "materials_applied": 0,
        "materials_removed": 0,
        "edges_added": 0,
        "edges_removed": 0,
        "hosts_updated": [],
        "hostless_bindings": 0,
        "unresolved_bindings": [],
        "skipped_materials": [],
        "pending_unlocks": [],
        "name_matches": [],
        "credential_reuse_linked": 0,
        "unlocks_applied": 0,
        "stores_projected": 0,
        "declared_projected": 0,
        "ecs_workloads": 0,
        "ecs_hosts": 0,
        "escape_surfaces": 0,
    }

    import_scope = _import_scope_key(report)
    prepared_by_binding: list[tuple[dict[str, Any], list[tuple[dict[str, Any], Any]]]] = []
    all_prepared: list[tuple[dict[str, Any], Any]] = []

    # Project TF-declared ECS/ASG/RDS topology before host fuzzy-resolve so
    # folder-style host_hint (e.g. module-2) can bind onto the goat workload.
    inv = project_declared_inventory(
        builder,
        declared_resources=report.get("declared_resources"),
        report=report,
    )
    for key in ("declared_projected", "ecs_workloads", "ecs_hosts", "escape_surfaces"):
        stats[key] = inv.get(key, 0)
    stats["edges_added"] += inv.get("edges_added", 0)

    for binding in report.get("bindings") or []:
        if not isinstance(binding, dict):
            continue
        prepared: list[tuple[dict[str, Any], Any]] = []
        for material in binding.get("materials") or []:
            if not isinstance(material, dict):
                continue
            kind = str(material.get("kind") or "")
            try:
                spec = get_material_kind(kind)
            except ValueError as exc:
                stats["skipped_materials"].append({"kind": kind, "error": str(exc)})
                continue
            prepared.append((material, spec))
        if prepared:
            prepared_by_binding.append((binding, prepared))
            all_prepared.extend(prepared)

    # Replace prior import of the same report / overlapping material keys first.
    cleared = _clear_prior_import(graph, import_scope=import_scope, prepared=all_prepared)
    stats["materials_removed"] += cleared["materials_removed"]
    stats["edges_removed"] += cleared["edges_removed"]

    for index, (binding, prepared) in enumerate(prepared_by_binding):
        host_id = _resolve_binding_target(
            graph,
            binding,
            report=report,
            materials=[m for m, _ in prepared],
            default_target_node_id=default_target_node_id,
        )
        if not host_id:
            # Still import materials + unlocks; HAS_MATERIAL waits for a host match.
            stats["hostless_bindings"] += 1
            if _binding_had_explicit_ref(binding) and not _binding_is_unbound(binding):
                stats["unresolved_bindings"].append(
                    {
                        "index": index,
                        "target_ref": binding.get("target_ref") or binding.get("target_node_id"),
                        "hint": "No unique fuzzy match for host ref — materials imported hostless",
                    }
                )

        host = graph.nodes.get(host_id) if host_id else None
        applied_kinds: list[str] = []

        for material, spec in prepared:
            kind = spec.kind
            locator = redact_secret_text(str(material.get("locator") or kind))
            if kind == "none_observed":
                if host:
                    _merge_host_enrichment_summary(host, kind=kind, locator=locator, report=report)
                    if host_id not in stats["hosts_updated"]:
                        stats["hosts_updated"].append(host_id)
                applied_kinds.append(kind)
                stats["materials_applied"] += 1
                continue

            # Re-stamp finding/summary from evidence so old reports get human labels.
            material = enrich_assess_item(dict(material))
            if material.get("summary") and is_weak_label(str(material["summary"]), kind=kind):
                material = enrich_assess_item(material)
            if kind == "k8s_service_account_token":
                material = enrich_sa_token_material(material)

            resolves_to = material.get("resolves_to")
            name_hints = [str(h) for h in (material.get("name_hints") or []) if h]
            typed_targets = list(material.get("impact_targets") or [])
            # Attach declared Secrets Manager vault names so Secret:* can UNLOCKS
            # typed targets with where=<vault> even if correlate omitted them.
            if typed_targets:
                target_names = {
                    str(t.get("name") or "").strip().lower()
                    for t in typed_targets
                    if isinstance(t, dict)
                }
                for row in report.get("declared_resources") or []:
                    if not isinstance(row, dict):
                        continue
                    if str(row.get("kind") or "") != "secretsmanager_secret":
                        continue
                    vault = str(row.get("name") or "").strip()
                    if vault and vault.lower() not in target_names and vault not in name_hints:
                        name_hints.append(vault)
            # Typed impact_targets skip fuzzy unlocks; otherwise resolve name hints.
            if typed_targets:
                matched_refs = []
            else:
                matched_refs = _resolve_name_hints(graph, name_hints, material_kind=kind)
                if not resolves_to:
                    resolves_to = _infer_unlock_target(graph, material, matched_refs)

            mat_native = material.get("id") or material_native_id(
                kind,
                locator,
                fingerprint=material.get("secret_fingerprint"),
                impact_key=material.get("impact_key") or _impact_key_from_material(material),
            )
            evidence = redact_evidence(material.get("evidence") or {})
            seen_at = _normalize_seen_at(
                locator,
                material.get("seen_at"),
                material.get("also_seen_in"),
            )
            # Locations live on HAS_MATERIAL edges when the secret is multi-site
            # or keyed by shared impact / fingerprint.
            location_on_edge = bool(
                len(seen_at) > 1
                or material.get("secret_fingerprint")
                or material.get("impact_key")
                or typed_targets
            )
            # Always derive labels from evidence — never keep catalog/kind-slug titles.
            label_props = material_detail_props(
                kind=kind,
                locator=locator,
                evidence=evidence,
                name_hints=name_hints or None,
                include_location=not location_on_edge,
            )
            stamped = material.get("summary")
            if stamped and not is_weak_label(str(stamped), kind=kind) and not location_on_edge:
                label_props["summary"] = str(stamped)
                label_props["display_name"] = str(stamped)
                label_props["name"] = str(stamped)
                if material.get("finding") and not is_weak_label(
                    str(material["finding"]), kind=kind
                ):
                    label_props["finding"] = str(material["finding"])
            elif location_on_edge and material.get("finding"):
                # Rebuild a location-free title even if the report stamped a pathful summary.
                finding = str(material.get("finding") or label_props.get("finding") or "")
                if finding and not is_weak_label(finding, kind=kind):
                    label_props["finding"] = finding
                label_props["summary"] = material_detail_props(
                    kind=kind,
                    locator=locator,
                    evidence={**evidence, "finding": label_props.get("finding") or finding},
                    name_hints=name_hints or None,
                    include_location=False,
                )["summary"]
                label_props["display_name"] = label_props["summary"]
                label_props["name"] = label_props["summary"]

            mat_props: dict[str, Any] = {
                "native_kind": "PivotMaterial",
                "material_kind": kind,
                "locator": locator,
                "seen_at": seen_at,
                "extends_blast_to": spec.extends_blast_to,
                "collector": report.get("collector"),
                "collector_mode": report.get("collector_mode"),
                "confidence": material.get("confidence") or "explicit",
                "evidence": evidence,
                "source": "collector-enrichment",
                "import_scope": import_scope,
                "unlock_pending": bool(spec.requires_target and not resolves_to),
                **label_props,
            }
            impact_key = material.get("impact_key") or _impact_key_from_material(material)
            if impact_key:
                mat_props["impact_key"] = impact_key
            if material.get("secret_fingerprint"):
                mat_props["secret_fingerprint"] = material["secret_fingerprint"]
            if material.get("material_kinds"):
                mat_props["material_kinds"] = list(material["material_kinds"])
            if len(seen_at) > 1 or material.get("reuse_count"):
                mat_props["reuse_count"] = max(len(seen_at), int(material.get("reuse_count") or 0))
                mat_props["also_seen_in"] = [s for s in seen_at if s != locator]
                stats["credential_reuse_linked"] += 1
            if name_hints:
                mat_props["name_hints"] = name_hints
            if typed_targets:
                mat_props["impact_targets"] = typed_targets
            if matched_refs:
                mat_props["matched_names"] = [
                    {"hint": hint, "node_id": nid} for hint, nid in matched_refs
                ]

            prior = _find_node_by_native_id(graph, mat_native)
            if prior:
                mat_props = _collapse_material_node_props(prior.props, mat_props)

            mat_id = builder.add_concept_node(
                concept_type=ConceptType.SECRET_STORE,
                native_id=mat_native,
                props=mat_props,
            )
            # Refresh props on upsert (add_concept_node may return existing).
            node = graph.nodes.get(mat_id)
            if node:
                node.props.update(mat_props)

            if host_id:
                edge_props = enrichment_edge_props(
                    source="collector",
                    material_kind=kind,
                    locator=locator,
                    seen_at=seen_at,
                    collector=report.get("collector"),
                    confidence=material.get("confidence") or "explicit",
                    import_scope=import_scope,
                )
                if material.get("secret_fingerprint"):
                    edge_props["secret_fingerprint"] = material["secret_fingerprint"]
                if impact_key:
                    edge_props["impact_key"] = impact_key
                stats["edges_added"] += int(
                    _upsert_edge(
                        builder,
                        graph,
                        host_id,
                        spec.host_rel,
                        mat_id,
                        edge_props,
                        merge_seen_at=True,
                    )
                )
                if host_id not in stats["hosts_updated"]:
                    stats["hosts_updated"].append(host_id)

            unlocked_ids: set[str] = set()

            # Typed impact: material -[UNLOCKS]-> named concrete target(s).
            impact = wire_credential_impact(
                builder,
                graph,
                material_node_id=mat_id,
                material_kind=kind,
                locator=locator,
                name_hints=name_hints,
                impact_targets=typed_targets,
                evidence=evidence,
                collector=report.get("collector"),
                unlock_rel=spec.unlock_rel,
            )
            stats["edges_added"] += int(impact["unlocks_applied"])
            stats["unlocks_applied"] += int(impact["unlocks_applied"])
            stats["stores_projected"] += int(impact.get("projected") or 0)
            for row in impact.get("targets") or []:
                unlocked_ids.add(row["node_id"])
                stats["name_matches"].append(
                    {
                        "hint": row["hint"],
                        "node_id": row["node_id"],
                        "material": locator,
                        "kind": row["kind"],
                        "match": "credential-impact",
                    }
                )

            # Without typed targets: fuzzy name hints may still unlock identities/secrets.
            if not typed_targets:
                for hint, node_id in matched_refs:
                    stats["name_matches"].append(
                        {"hint": hint, "node_id": node_id, "material": locator}
                    )
                    if node_id in unlocked_ids:
                        continue
                    if _is_unlock_target(graph, node_id):
                        added = _upsert_edge(
                            builder,
                            graph,
                            mat_id,
                            spec.unlock_rel,
                            node_id,
                            enrichment_edge_props(
                                source="collector",
                                material_kind=kind,
                                locator=locator,
                                name_hint=hint,
                                match="fuzzy-name",
                                mechanism="credential-maps-to",
                                collector=report.get("collector"),
                                confidence="inferred",
                            ),
                        )
                        stats["edges_added"] += int(added)
                        if added:
                            stats["unlocks_applied"] += 1
                        unlocked_ids.add(node_id)
                    else:
                        stats["edges_added"] += int(
                            _upsert_edge(
                                builder,
                                graph,
                                mat_id,
                                "REFERENCES",
                                node_id,
                                enrichment_edge_props(
                                    source="collector",
                                    material_kind=kind,
                                    locator=locator,
                                    name_hint=hint,
                                    match="fuzzy-name",
                                    collector=report.get("collector"),
                                    confidence="inferred",
                                ),
                            )
                        )

            if resolves_to and not typed_targets:
                existing = resolve_node_ref(
                    graph,
                    str(resolves_to),
                    prefer_concepts=prefer_concepts_for_material(kind) or ("identity",),
                )
                if existing:
                    target_id = existing
                else:
                    target_concept = infer_concept_type(str(resolves_to)) or ConceptType.IDENTITY
                    target_id = builder.add_concept_node(
                        concept_type=target_concept,
                        native_id=str(resolves_to),
                        props={"display_name": str(resolves_to), "source": "collector-enrichment"},
                    )
                if target_id not in unlocked_ids:
                    added = _upsert_edge(
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
                    stats["edges_added"] += int(added)
                    if added:
                        stats["unlocks_applied"] += 1
                    unlocked_ids.add(target_id)

            if unlocked_ids:
                mat_node = graph.nodes.get(mat_id)
                if mat_node:
                    mat_node.props["unlock_pending"] = False
                    mat_node.props["unlock_targets"] = sorted(unlocked_ids)
            elif spec.requires_target:
                stats["pending_unlocks"].append(
                    {
                        "kind": kind,
                        "locator": locator,
                        "host_id": host_id,
                        "name_hints": name_hints,
                        "hint": "No unique identity/store match yet — re-import after enum or pass resolves_to",
                    }
                )

            applied_kinds.append(kind)
            stats["materials_applied"] += 1

        if applied_kinds and host:
            _merge_host_enrichment_summary(
                host,
                kind=applied_kinds[-1],
                locator=redact_secret_text(str(prepared[-1][0].get("locator") if prepared else "")),
                report=report,
                material_kinds=applied_kinds,
                material_count=len(applied_kinds),
            )
            stats["bindings_applied"] += 1
        elif applied_kinds:
            stats["bindings_applied"] += 1

    stats["enrichment_edges_marked"] = mark_enrichment_edges(builder.snapshot)
    return stats


def _import_scope_key(report: dict[str, Any]) -> str:
    collector = str(report.get("collector") or "collector")
    mode = str(report.get("collector_mode") or "")
    root = str(report.get("source_root") or report.get("host_hint") or "")
    return f"{collector}|{mode}|{root}"


def _clear_prior_import(
    graph: GraphSnapshot,
    *,
    import_scope: str,
    prepared: list[tuple[dict[str, Any], Any]],
) -> dict[str, int]:
    """Drop collector materials that this import will replace."""
    result = {"materials_removed": 0, "edges_removed": 0}
    incoming_ids: set[str] = set()
    incoming_keys: set[tuple[str, str]] = set()
    incoming_fps: set[str] = set()
    for material, spec in prepared:
        if spec.kind == "none_observed":
            continue
        locator = redact_secret_text(str(material.get("locator") or spec.kind))
        fp = material.get("secret_fingerprint")
        if isinstance(fp, str) and fp.strip():
            incoming_fps.add(fp.strip())
        impact_key = material.get("impact_key") or _impact_key_from_material(material)
        native = material.get("id") or material_native_id(
            spec.kind,
            locator,
            fingerprint=fp if isinstance(fp, str) else None,
            impact_key=impact_key,
        )
        incoming_ids.add(str(native))
        incoming_keys.add((spec.kind, locator))
        for loc in material.get("seen_at") or []:
            incoming_keys.add((spec.kind, redact_secret_text(str(loc))))

    remove: list[str] = []
    for node_id, node in list(graph.nodes.items()):
        if node.props.get("source") != "collector-enrichment":
            continue
        if not node.props.get("material_kind"):
            continue
        native = str(node.props.get("native_id") or "")
        kind = str(node.props.get("material_kind") or "")
        locator = str(node.props.get("locator") or "")
        node_fp = str(node.props.get("secret_fingerprint") or "")
        node_impact = str(node.props.get("impact_key") or "")
        if native in incoming_ids or (kind, locator) in incoming_keys:
            remove.append(node_id)
        elif node_fp and node_fp in incoming_fps:
            # Migrate location-keyed nodes onto fingerprint identity on re-import.
            remove.append(node_id)
        elif node_impact and any(
            str(material.get("impact_key") or _impact_key_from_material(material) or "") == node_impact
            for material, _spec in prepared
        ):
            remove.append(node_id)
        elif node.props.get("import_scope") == import_scope:
            remove.append(node_id)

    for material_id in dict.fromkeys(remove):
        edge_count = sum(
            1 for edge in graph.edges if edge.src_id == material_id or edge.dst_id == material_id
        )
        if graph.remove_node(material_id):
            result["materials_removed"] += 1
            result["edges_removed"] += edge_count
    return result


def _resolve_name_hints(
    graph: GraphSnapshot,
    hints: list[str],
    *,
    material_kind: str | None = None,
) -> list[tuple[str, str]]:
    """Map rough Terraform/cloud names onto existing graph nodes (fuzzy).

    Tries the material's preferred concepts first, then a second pass for
    datastore/secret/identity so DB passwords can hit RDS and Secrets alike.
    """
    prefer = prefer_concepts_for_material(material_kind)
    extra_passes: list[tuple[str, ...]] = [()]
    if (material_kind or "").lower() in {"database_connection_string", "generic_credential_file"}:
        extra_passes = [
            ("datastore", "rds", "dbinstance"),
            ("secretstore", "secret"),
            ("identity", "role", "user"),
        ]
    matched: list[tuple[str, str]] = []
    seen_nodes: set[str] = set()
    for hint in hints:
        for prefer_set in (prefer, *extra_passes):
            node_id = resolve_node_ref(
                graph,
                hint,
                prefer_concepts=prefer_set or None,
            )
            if not node_id or node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)
            matched.append((hint, node_id))
            break
    return matched


def _is_unlock_target(graph: GraphSnapshot, node_id: str) -> bool:
    """Targets that harvested creds can reach in blast radius."""
    node = graph.nodes.get(node_id)
    if not node:
        return False
    concept = str(node.props.get("concept_type") or "")
    if concept in {"Identity", "SecretStore", "DataStore", "RegistryStore"}:
        return True
    rtype = str(node.props.get("resource_type") or node.props.get("native_kind") or "").lower()
    return any(
        tok in rtype
        for tok in ("secret", "rds", "db", "dynamo", "s3", "bucket", "database", "role", "user")
    )


def _infer_unlock_target(
    graph: GraphSnapshot,
    material: dict[str, Any],
    matched_refs: list[tuple[str, str]],
) -> str | None:
    for _hint, node_id in matched_refs:
        node = graph.nodes.get(node_id)
        if node and node.props.get("concept_type") == "Identity":
            return str(node.props.get("native_id") or node.props.get("arn") or node_id)

    evidence = material.get("evidence") or {}
    for key in ("resolves_to", "principal", "role", "user", "identity", "arn"):
        val = evidence.get(key)
        if val:
            hit = resolve_node_ref(graph, str(val), prefer_concepts=("identity", "role", "user"))
            if hit:
                node = graph.nodes[hit]
                return str(node.props.get("native_id") or node.props.get("arn") or hit)
    return None


def _resolve_binding_target(
    graph: GraphSnapshot,
    binding: dict[str, Any],
    *,
    report: dict[str, Any],
    materials: list[dict[str, Any]],
    default_target_node_id: str | None,
) -> str | None:
    """Fuzzy-resolve a host/compute node for HAS_MATERIAL."""
    if default_target_node_id and default_target_node_id in graph.nodes:
        return default_target_node_id

    if binding.get("target_node_id"):
        node_id = str(binding["target_node_id"])
        if node_id in graph.nodes:
            return node_id
        hit = resolve_node_ref(graph, node_id, prefer_concepts=_HOST_PREFER)
        if hit and _is_host_like(graph, hit):
            return hit

    candidates: list[str] = []
    for key in ("target_ref", "host_ref", "host_name", "host"):
        val = binding.get(key)
        if val and str(val).strip().lower() not in _UNBOUND_REFS:
            candidates.append(str(val).strip())

    for key in ("host_hint", "host", "hostname", "name", "collect_name"):
        val = report.get(key)
        if val and str(val).strip().lower() not in _UNBOUND_REFS:
            candidates.append(str(val).strip())

    source_root = report.get("source_root")
    if source_root:
        name = Path(str(source_root)).name
        if name:
            candidates.append(name)

    for material in materials:
        evidence = material.get("evidence") or {}
        for key in ("host", "hostname", "instance_id", "node", "target"):
            if evidence.get(key):
                candidates.append(str(evidence[key]))
        # Do not use name_hints as host candidates — those are unlock targets (RDS/secrets).

    seen: set[str] = set()
    for ref in candidates:
        if not ref or ref.lower() in seen or ref.lower() in _UNBOUND_REFS:
            continue
        seen.add(ref.lower())
        hit = resolve_node_ref(graph, ref, prefer_concepts=_HOST_PREFER)
        if hit and _is_host_like(graph, hit):
            return hit
        # Allow Identity only when the ref explicitly looks like a host alias? No.

    # Exactly one compromised / scenario-start host in the session.
    starts = [
        nid
        for nid, n in graph.nodes.items()
        if n.props.get("is_scenario_start")
        or n.props.get("native_kind") == "CompromisedHost"
        or n.props.get("pivot_surface") == "host"
    ]
    if len(starts) == 1:
        return starts[0]

    # Folder-style host_hint / unbound collect → projected ECS workload or ASG host.
    return preferred_enrichment_host(graph)


def _is_host_like(graph: GraphSnapshot, node_id: str) -> bool:
    node = graph.nodes.get(node_id)
    if not node:
        return False
    concept = str(node.props.get("concept_type") or "")
    if concept in _HOST_CONCEPTS:
        return True
    rtype = str(node.props.get("resource_type") or node.props.get("native_kind") or "").lower()
    return any(
        tok in rtype
        for tok in (
            "ec2",
            "lambda",
            "ecs",
            "host",
            "instance",
            "workload",
            "pod",
            "container",
            "comput",
        )
    )


def _binding_is_unbound(binding: dict[str, Any]) -> bool:
    ref = str(binding.get("target_ref") or "").strip().lower()
    return (not ref or ref in _UNBOUND_REFS) and not binding.get("target_node_id")


def _binding_had_explicit_ref(binding: dict[str, Any]) -> bool:
    return bool(binding.get("target_node_id") or binding.get("host_ref") or binding.get("host_name"))


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
    if kind == "none_observed" and set(kinds) <= {"none_observed"}:
        host.props["enrichment_status"] = "clean"
    else:
        host.props["enrichment_status"] = "material_found"


def _upsert_edge(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    src_id: str,
    rel_type: str,
    dst_id: str,
    props: dict[str, Any],
    *,
    merge_seen_at: bool = False,
) -> bool:
    for dst, rel, existing in graph.adjacency.get(src_id, []):
        if dst == dst_id and rel == rel_type:
            if merge_seen_at:
                _merge_seen_at_props(existing, props)
            else:
                existing.update(props)
            return False
    builder.add_edge(src_id=src_id, rel_type=rel_type, dst_id=dst_id, props=props)
    return True


def _normalize_seen_at(
    locator: str,
    seen_at: Any = None,
    also_seen_in: Any = None,
) -> list[str]:
    out: list[str] = []
    for raw in (locator, *(seen_at or []), *(also_seen_in or [])):
        text = redact_secret_text(str(raw)) if raw else ""
        if text and text not in out:
            out.append(text)
    return out


def _impact_key_from_material(material: dict[str, Any]) -> str | None:
    from samoyed.collectors.correlate import db_impact_key

    return db_impact_key(material)


def _merge_seen_at_props(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Merge observation sites onto an existing edge; keep other incoming props."""
    seen = _normalize_seen_at(
        str(incoming.get("locator") or existing.get("locator") or ""),
        existing.get("seen_at"),
        incoming.get("seen_at"),
    )
    also = existing.get("also_seen_in") or []
    if isinstance(also, list):
        for loc in also:
            text = str(loc)
            if text and text not in seen:
                seen.append(text)
    merged = dict(incoming)
    merged["seen_at"] = seen
    if seen:
        merged["locator"] = incoming.get("locator") or existing.get("locator") or seen[0]
        if len(seen) > 1:
            merged["also_seen_in"] = [s for s in seen if s != merged["locator"]]
    existing.update(merged)


def _find_node_by_native_id(graph: GraphSnapshot, native_id: str) -> Any | None:
    for node in graph.nodes.values():
        if str(node.props.get("native_id") or "") == native_id:
            return node
    return None


def _collapse_material_node_props(
    prior: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    """Merge a second observation of the same fingerprint into prior node props."""
    merged = dict(prior)
    seen = _normalize_seen_at(
        str(incoming.get("locator") or ""),
        prior.get("seen_at"),
        incoming.get("seen_at"),
    )
    for loc in prior.get("also_seen_in") or []:
        text = str(loc)
        if text and text not in seen:
            seen.append(text)
    # Prefer incoming labels/kind when present (caller already chose primary).
    for key, value in incoming.items():
        if key in {"seen_at", "also_seen_in", "reuse_count", "material_kinds", "name_hints"}:
            continue
        if value is not None:
            merged[key] = value
    merged["seen_at"] = seen
    locator = str(incoming.get("locator") or merged.get("locator") or "")
    if locator:
        merged["locator"] = locator
    if len(seen) > 1:
        merged["reuse_count"] = max(len(seen), int(prior.get("reuse_count") or 0), int(incoming.get("reuse_count") or 0))
        merged["also_seen_in"] = [s for s in seen if s != merged.get("locator")]
    kinds: list[str] = []
    for source in (prior, incoming):
        for kind in (
            source.get("material_kind"),
            *(source.get("material_kinds") or []),
        ):
            text = str(kind) if kind else ""
            if text and text not in kinds:
                kinds.append(text)
    if kinds:
        merged["material_kinds"] = kinds
    hints: list[str] = []
    for source in (prior, incoming):
        for hint in source.get("name_hints") or []:
            text = str(hint)
            if text and text not in hints:
                hints.append(text)
    if hints:
        merged["name_hints"] = hints
    return merged
