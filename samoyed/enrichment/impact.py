"""Map harvested DB credentials onto the RDS / database instance they unlock.

Password and connection-string materials blast to the **database server**
(``aws_db_instance`` / RDS identifier) — not Secrets Manager secret names like
``RDS_CREDS``, which are meaningless as an impact target.
"""

from __future__ import annotations

import re
from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.refs import resolve_node_ref

_DB_CRED_KINDS = frozenset({"database_connection_string", "generic_credential_file"})
_DBISH = re.compile(
    r"(?i)(?:^|[-_])(?:db|mysql|postgres|aurora|database)(?:$|[-_])|"
    r"(?:^|[-_])rds(?:$|[-_])|"  # rds / …-rds / rds-… but not RDS_CREDS
    r"goat-db|-db$"
)
_SECRET_NAME = re.compile(r"(?i)cred|secret|password|passwd|token|vault")


def is_db_credential_kind(kind: str | None) -> bool:
    return (kind or "").lower() in _DB_CRED_KINDS


def declared_by_name(declared_resources: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in declared_resources or []:
        name = str(row.get("name") or "").strip()
        if name:
            out[name] = row
    return out


def classify_db_hint(
    hint: str,
    *,
    declared: dict[str, dict[str, Any]] | None = None,
) -> bool:
    """True when ``hint`` names a database instance (not a secret/role)."""
    name = (hint or "").strip()
    if not name:
        return False
    row = (declared or {}).get(name)
    if row:
        return str(row.get("kind") or "") == "db_instance"
    # Never treat Secrets Manager-style names as the DB.
    if _SECRET_NAME.search(name):
        return False
    return bool(_DBISH.search(name))


def impact_targets_for_material(
    *,
    kind: str,
    name_hints: list[str] | None = None,
    impact_targets: list[dict[str, Any]] | None = None,
    declared_resources: list[dict[str, Any]] | None = None,
    evidence: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """DB credential → RDS/database instance only."""
    _ = evidence
    if not is_db_credential_kind(kind):
        return []

    declared = declared_by_name(declared_resources)
    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        key = name.lower()
        if not name or key in seen:
            return
        if not classify_db_hint(name, declared=declared):
            return
        seen.add(key)
        targets.append({"name": name, "kind": "db_instance"})

    for row in impact_targets or []:
        if str(row.get("kind") or "") == "db_instance":
            _add(str(row.get("name") or "").strip())

    for name, row in declared.items():
        if str(row.get("kind") or "") == "db_instance":
            _add(name)

    for hint in name_hints or []:
        _add(str(hint).strip())

    return targets


def ensure_impact_target_node(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    name: str,
    store_kind: str = "db_instance",
) -> str:
    """Resolve an existing RDS/DataStore or project the database instance."""
    _ = store_kind
    prefer = ("datastore", "rds", "dbinstance", "database")
    existing = resolve_node_ref(graph, name, prefer_concepts=prefer)
    if existing and _is_concrete_rds(graph, existing):
        return existing

    native_id = f"RDSInstance:{name}"
    return builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id=native_id,
        props={
            "resource_type": "RDSInstance",
            "native_kind": "RDSInstance",
            "name": name,
            "display_name": name,
            "db_instance_identifier": name,
            "source": "collector-enrichment",
            "projected": True,
            "projected_reason": "credential-impact",
            "is_high_value": True,
            "high_value_source": "credential-impact",
        },
    )


def wire_credential_impact(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    material_node_id: str,
    material_kind: str,
    locator: str,
    name_hints: list[str] | None = None,
    impact_targets: list[dict[str, Any]] | None = None,
    declared_resources: list[dict[str, Any]] | None = None,
    evidence: dict[str, Any] | None = None,
    collector: str | None = None,
    unlock_rel: str = "UNLOCKS",
) -> dict[str, Any]:
    """UNLOCKS from a DB password material to the RDS instance only."""
    stats: dict[str, Any] = {
        "unlocks_applied": 0,
        "projected": 0,
        "pruned": 0,
        "targets": [],
    }
    if not is_db_credential_kind(material_kind):
        return stats

    stats["pruned"] = _prune_non_rds_unlocks(graph, material_node_id)

    targets = impact_targets_for_material(
        kind=material_kind,
        name_hints=name_hints,
        impact_targets=impact_targets,
        declared_resources=declared_resources,
        evidence=evidence,
    )
    unlocked: list[str] = []
    for target in targets:
        before_ids = set(graph.nodes)
        node_id = ensure_impact_target_node(
            builder,
            graph,
            name=target["name"],
            store_kind="db_instance",
        )
        if node_id not in before_ids:
            stats["projected"] += 1

        added = _upsert_unlock(
            builder,
            graph,
            material_node_id,
            unlock_rel,
            node_id,
            enrichment_edge_props(
                source="collector",
                material_kind=material_kind,
                locator=locator,
                name_hint=target["name"],
                store_kind="db_instance",
                match="credential-impact",
                mechanism="credential-maps-to-rds",
                collector=collector,
                confidence="inferred",
            ),
        )
        if added:
            stats["unlocks_applied"] += 1
        unlocked.append(node_id)
        stats["targets"].append({"hint": target["name"], "kind": "db_instance", "node_id": node_id})

    mat = graph.nodes.get(material_node_id)
    if mat and unlocked:
        mat.props["unlock_pending"] = False
        mat.props["unlock_targets"] = sorted(set(unlocked))
        mat.props["impact_targets"] = targets
    return stats


def repair_credential_impact(
    builder: GraphBuilder,
    *,
    declared_resources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Re-wire DB password materials → RDS only (session repair)."""
    graph = builder.snapshot
    stats = {
        "materials": 0,
        "unlocks_applied": 0,
        "projected": 0,
        "pruned": 0,
        "junk_projected_removed": 0,
    }
    stats["junk_projected_removed"] = _remove_junk_projected_rds(graph)

    for node_id, node in list(graph.nodes.items()):
        kind = str(node.props.get("material_kind") or "")
        if node.props.get("native_kind") != "PivotMaterial" and not kind:
            continue
        if not is_db_credential_kind(kind):
            continue
        result = wire_credential_impact(
            builder,
            graph,
            material_node_id=node_id,
            material_kind=kind,
            locator=str(node.props.get("locator") or ""),
            name_hints=list(node.props.get("name_hints") or []),
            impact_targets=list(node.props.get("impact_targets") or []),
            declared_resources=declared_resources,
            evidence=node.props.get("evidence") if isinstance(node.props.get("evidence"), dict) else {},
            collector=str(node.props.get("collector") or "collector"),
        )
        stats["materials"] += 1
        stats["unlocks_applied"] += int(result["unlocks_applied"])
        stats["projected"] += int(result["projected"])
        stats["pruned"] += int(result.get("pruned") or 0)
    return stats


def _remove_junk_projected_rds(graph: GraphSnapshot) -> int:
    """Drop projected 'RDSInstance:RDS_CREDS'-style nodes (secret names mistaken for DBs)."""
    remove: list[str] = []
    for node_id, node in list(graph.nodes.items()):
        if not node.props.get("projected"):
            continue
        if str(node.props.get("resource_type") or "") != "RDSInstance":
            continue
        name = str(
            node.props.get("db_instance_identifier")
            or node.props.get("name")
            or node.props.get("display_name")
            or ""
        )
        if _SECRET_NAME.search(name) or not classify_db_hint(name):
            remove.append(node_id)
    for node_id in remove:
        graph.remove_node(node_id)
    return len(remove)


def _prune_non_rds_unlocks(graph: GraphSnapshot, material_node_id: str) -> int:
    """Drop password→role / password→secret unlocks; keep only RDS/DataStore."""
    keep: list = []
    removed = 0
    for edge in graph.edges:
        if edge.src_id != material_node_id or edge.rel_type != "UNLOCKS":
            keep.append(edge)
            continue
        if _is_concrete_rds(graph, edge.dst_id):
            keep.append(edge)
            continue
        removed += 1
    if removed:
        graph.edges[:] = keep
        if hasattr(graph, "adjacency") and material_node_id in graph.adjacency:
            graph.adjacency[material_node_id] = [
                (e.dst_id, e.rel_type, e.props)
                for e in graph.edges
                if e.src_id == material_node_id
            ]
    return removed


def _is_concrete_rds(graph: GraphSnapshot, node_id: str) -> bool:
    node = graph.nodes.get(node_id)
    if not node:
        return False
    if node.props.get("native_kind") == "PivotMaterial" or node.props.get("material_kind"):
        return False
    name = str(
        node.props.get("db_instance_identifier")
        or node.props.get("name")
        or node.props.get("display_name")
        or ""
    )
    # Reject secret names that were wrongly projected as RDSInstance:*
    if name and _SECRET_NAME.search(name):
        return False
    concept = str(node.props.get("concept_type") or "")
    rtype = str(node.props.get("resource_type") or node.props.get("native_kind") or "").lower()
    if concept == "DataStore":
        return any(tok in rtype for tok in ("rds", "db", "database", "aurora")) or bool(
            name and classify_db_hint(name)
        )
    return any(tok in rtype for tok in ("rds", "dbinstance", "database", "aurora"))


def _upsert_unlock(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    src: str,
    rel: str,
    dst: str,
    props: dict[str, Any],
) -> bool:
    for edge in graph.edges:
        if edge.src_id == src and edge.dst_id == dst and edge.rel_type == rel:
            edge.props.update(props)
            return False
    builder.add_edge(src_id=src, rel_type=rel, dst_id=dst, props=props)
    return True
