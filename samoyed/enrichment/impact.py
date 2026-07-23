"""Map harvested credentials onto the concrete nodes they unlock.

Mental model: a credential is a traversal token, not a crown jewel.
  host -[HAS_MATERIAL]-> material -[UNLOCKS]-> namedTarget

Collectors emit ``impact_targets: [{kind, name}]`` with the full concrete
target name. Free-form ``name_hints`` are for labels/UI only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from samoyed.cloud.concepts import ConceptType
from samoyed.credentials.k8s import sa_native_id
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.enrichment import enrichment_edge_props
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.refs import resolve_node_ref

_DB_CRED_KINDS = frozenset({"database_connection_string", "generic_credential_file"})


@dataclass(frozen=True)
class ImpactKindSpec:
    """How to resolve/project a typed impact target kind."""

    kind: str
    concept: ConceptType
    resource_type: str
    prefer_concepts: tuple[str, ...]
    native_id: Callable[[str], str]
    extra_props: Callable[[str], dict[str, Any]]
    mark_high_value: bool = False


def _rds_props(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "display_name": name,
        "db_instance_identifier": name,
        "is_high_value": True,
        "high_value_source": "credential-impact",
    }


def _named_props(name: str) -> dict[str, Any]:
    return {"name": name, "display_name": name}


def _bucket_props(name: str) -> dict[str, Any]:
    return {"name": name, "display_name": name, "bucket_name": name}


def _role_props(name: str) -> dict[str, Any]:
    return {"name": name, "display_name": name, "native_kind": "Role"}


def _user_props(name: str) -> dict[str, Any]:
    return {"name": name, "display_name": name, "native_kind": "User"}


def _ec2_props(name: str) -> dict[str, Any]:
    return {"name": name, "display_name": name, "instance_id": name}


def _external_service_props(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "display_name": name,
        "service": name,
        "is_external": True,
        "boundary": "external",
    }


def _email_account_props(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "display_name": name,
        "mailbox": name,
        "is_external": True,
        "boundary": "external",
    }


def _k8s_sa_native_id(name: str) -> str:
    text = str(name or "").strip()
    if text.startswith("kubernetes:serviceaccount:"):
        return text
    if ":" in text:
        ns, sa = text.split(":", 1)
        return sa_native_id(ns, sa)
    return sa_native_id("default", text)


def _k8s_sa_props(name: str) -> dict[str, Any]:
    native = _k8s_sa_native_id(name)
    parts = native.split(":")
    ns = parts[2] if len(parts) >= 4 else "default"
    sa = parts[3] if len(parts) >= 4 else str(name)
    return {
        "name": sa,
        "display_name": f"{ns}/{sa}",
        "namespace": ns,
        "native_kind": "ServiceAccount",
    }


IMPACT_KIND_REGISTRY: dict[str, ImpactKindSpec] = {
    "db_instance": ImpactKindSpec(
        kind="db_instance",
        concept=ConceptType.DATA_STORE,
        resource_type="RDSInstance",
        prefer_concepts=("datastore", "rds", "dbinstance", "database"),
        native_id=lambda n: f"RDSInstance:{n}",
        extra_props=_rds_props,
        mark_high_value=True,
    ),
    "s3_bucket": ImpactKindSpec(
        kind="s3_bucket",
        concept=ConceptType.DATA_STORE,
        resource_type="S3Bucket",
        prefer_concepts=("datastore", "s3", "bucket"),
        native_id=lambda n: f"S3Bucket:{n}",
        extra_props=_bucket_props,
    ),
    "secretsmanager_secret": ImpactKindSpec(
        kind="secretsmanager_secret",
        concept=ConceptType.SECRET_STORE,
        resource_type="Secret",
        prefer_concepts=("secretstore", "secret"),
        native_id=lambda n: f"Secret:{n}",
        extra_props=_named_props,
    ),
    "iam_role": ImpactKindSpec(
        kind="iam_role",
        concept=ConceptType.IDENTITY,
        resource_type="Role",
        prefer_concepts=("identity", "role"),
        native_id=lambda n: f"Role:{n}",
        extra_props=_role_props,
    ),
    "iam_user": ImpactKindSpec(
        kind="iam_user",
        concept=ConceptType.IDENTITY,
        resource_type="User",
        prefer_concepts=("identity", "user"),
        native_id=lambda n: f"User:{n}",
        extra_props=_user_props,
    ),
    "lambda_function": ImpactKindSpec(
        kind="lambda_function",
        concept=ConceptType.RUNTIME_BINDING,
        resource_type="LambdaFunction",
        prefer_concepts=("runtimebinding", "lambda"),
        native_id=lambda n: f"LambdaFunction:{n}",
        extra_props=_named_props,
    ),
    "ec2_instance": ImpactKindSpec(
        kind="ec2_instance",
        concept=ConceptType.RUNTIME_BINDING,
        resource_type="EC2Instance",
        prefer_concepts=("runtimebinding", "ec2", "instance"),
        native_id=lambda n: f"EC2Instance:{n}",
        extra_props=_ec2_props,
    ),
    "ecs_cluster": ImpactKindSpec(
        kind="ecs_cluster",
        concept=ConceptType.RUNTIME_BINDING,
        resource_type="ECSCluster",
        prefer_concepts=("runtimebinding", "ecs"),
        native_id=lambda n: f"ECSCluster:{n}",
        extra_props=_named_props,
    ),
    "ecs_service": ImpactKindSpec(
        kind="ecs_service",
        concept=ConceptType.RUNTIME_BINDING,
        resource_type="ECSService",
        prefer_concepts=("runtimebinding", "ecs"),
        native_id=lambda n: f"ECSService:{n}",
        extra_props=_named_props,
    ),
    "ecs_task_definition": ImpactKindSpec(
        kind="ecs_task_definition",
        concept=ConceptType.RUNTIME_BINDING,
        resource_type="ECSTaskDefinition",
        prefer_concepts=("runtimebinding", "ecs"),
        native_id=lambda n: f"ECSTaskDefinition:{n}",
        extra_props=_named_props,
    ),
    "k8s_service_account": ImpactKindSpec(
        kind="k8s_service_account",
        concept=ConceptType.IDENTITY,
        resource_type="ServiceAccount",
        prefer_concepts=("identity", "serviceaccount", "kubernetes"),
        native_id=_k8s_sa_native_id,
        extra_props=_k8s_sa_props,
    ),
    # Credentials frequently pivot *out* of the cloud — a leaked API key or OAuth
    # token unlocks a third-party SaaS/API, and mailbox creds unlock an email
    # service. These land as external ManagementEndpoint nodes so the blast graph
    # shows the reachable off-cloud surface without pretending it is in-account.
    "external_service": ImpactKindSpec(
        kind="external_service",
        concept=ConceptType.MANAGEMENT_ENDPOINT,
        resource_type="ExternalService",
        prefer_concepts=("managementendpoint", "externalservice", "external", "service"),
        native_id=lambda n: f"ExternalService:{n}",
        extra_props=_external_service_props,
    ),
    "email_account": ImpactKindSpec(
        kind="email_account",
        concept=ConceptType.MANAGEMENT_ENDPOINT,
        resource_type="EmailAccount",
        prefer_concepts=("managementendpoint", "emailaccount", "email", "external"),
        native_id=lambda n: f"EmailAccount:{n}",
        extra_props=_email_account_props,
    ),
}


def is_db_credential_kind(kind: str | None) -> bool:
    """Legacy helper for password-ish findings (labels / UI). Not an unlock gate."""
    return (kind or "").lower() in _DB_CRED_KINDS


def get_impact_kind(kind: str | None) -> ImpactKindSpec | None:
    return IMPACT_KIND_REGISTRY.get(str(kind or "").strip())


def declared_by_name(declared_resources: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in declared_resources or []:
        name = str(row.get("name") or "").strip()
        if name:
            out[name] = row
    return out


def impact_targets_for_material(
    *,
    kind: str | None = None,
    name_hints: list[str] | None = None,
    impact_targets: list[dict[str, Any]] | None = None,
    declared_resources: list[dict[str, Any]] | None = None,
    evidence: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Return explicit registered impact targets only (ignore name_hints / declared sweep)."""
    _ = kind
    _ = evidence
    _ = name_hints
    _ = declared_resources

    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in _coerce_impact_target_rows(impact_targets):
        target_kind = str(row.get("kind") or "").strip()
        name = str(row.get("name") or "").strip()
        if not name or not get_impact_kind(target_kind):
            continue
        key = f"{target_kind}:{name.lower()}"
        if key in seen:
            continue
        seen.add(key)
        targets.append({"name": name, "kind": target_kind})
    return targets


def _coerce_impact_target_rows(raw: Any) -> list[dict[str, Any]]:
    """Normalize impact_targets after Neo4j JSON round-trip (str / list[str] / list[dict])."""
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for row in raw:
        if isinstance(row, str):
            try:
                row = json.loads(row)
            except (json.JSONDecodeError, TypeError):
                continue
        if isinstance(row, dict):
            out.append(row)
    return out


def _coerce_str_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(x) for x in parsed if x]
        except (json.JSONDecodeError, TypeError):
            return [raw] if raw else []
    if isinstance(raw, list):
        return [str(x) for x in raw if x]
    return []


def _coerce_evidence(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw[:1] == "{":
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


def ensure_impact_target_node(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    name: str,
    kind: str,
    store_kind: str | None = None,
) -> str:
    """Resolve an existing node for ``kind`` or project a concrete named stub."""
    target_kind = store_kind or kind
    spec = get_impact_kind(target_kind)
    if not spec:
        raise ValueError(f"unknown impact kind: {target_kind}")

    existing = resolve_node_ref(graph, name, prefer_concepts=spec.prefer_concepts)
    if existing and _is_concrete_target(graph, existing, target_kind):
        return existing

    native_id = spec.native_id(name)
    props = {
        "resource_type": spec.resource_type,
        "native_kind": spec.resource_type,
        "source": "collector-enrichment",
        "projected": True,
        "projected_reason": "credential-impact",
        **spec.extra_props(name),
    }
    if spec.mark_high_value:
        props.setdefault("is_high_value", True)
        props.setdefault("high_value_source", "credential-impact")
    return builder.add_concept_node(
        concept_type=spec.concept,
        native_id=native_id,
        props=props,
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
    """UNLOCKS from a material to typed concrete targets (any registered kind)."""
    stats: dict[str, Any] = {
        "unlocks_applied": 0,
        "projected": 0,
        "pruned": 0,
        "targets": [],
    }
    targets = impact_targets_for_material(
        kind=material_kind,
        name_hints=name_hints,
        impact_targets=impact_targets,
        declared_resources=declared_resources,
        evidence=evidence,
    )
    if not targets:
        return stats

    desired: set[str] = set()
    unlocked: list[str] = []
    for target in targets:
        before_ids = set(graph.nodes)
        node_id = ensure_impact_target_node(
            builder,
            graph,
            name=target["name"],
            kind=target["kind"],
        )
        if node_id not in before_ids:
            stats["projected"] += 1
        desired.add(node_id)

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
                store_kind=target["kind"],
                match="credential-impact",
                mechanism="credential-impact",
                collector=collector,
                confidence="inferred",
            ),
        )
        if added:
            stats["unlocks_applied"] += 1
        unlocked.append(node_id)
        stats["targets"].append(
            {"hint": target["name"], "kind": target["kind"], "node_id": node_id}
        )

    # Stolen SA token → IRSA IAM role via AssumeRoleWithWebIdentity (graph-inferred).
    if (material_kind or "").lower() == "k8s_service_account_token":
        irsa = _wire_irsa_web_identity_unlocks(
            builder,
            graph,
            material_node_id=material_node_id,
            sa_node_ids=list(unlocked),
            locator=locator,
            collector=collector,
            unlock_rel=unlock_rel,
        )
        stats["unlocks_applied"] += int(irsa.get("unlocks_applied") or 0)
        desired.update(irsa.get("role_ids") or [])
        unlocked.extend(irsa.get("role_ids") or [])
        stats.setdefault("irsa_web_identity_unlocks", 0)
        stats["irsa_web_identity_unlocks"] = int(irsa.get("unlocks_applied") or 0)

    stats["pruned"] = _prune_stale_unlocks(graph, material_node_id, desired)

    mat = graph.nodes.get(material_node_id)
    if mat and unlocked:
        mat.props["unlock_pending"] = False
        mat.props["unlock_targets"] = sorted(set(unlocked))
        mat.props["impact_targets"] = targets
    return stats


def _wire_irsa_web_identity_unlocks(
    builder: GraphBuilder,
    graph: GraphSnapshot,
    *,
    material_node_id: str,
    sa_node_ids: list[str],
    locator: str,
    collector: str | None,
    unlock_rel: str,
) -> dict[str, Any]:
    """UNLOCKS IAM roles that an unlocked SA PROJECTS_TO via IRSA."""
    stats: dict[str, Any] = {"unlocks_applied": 0, "role_ids": []}
    role_ids: list[str] = []
    for sa_id in sa_node_ids:
        sa = graph.nodes.get(sa_id)
        if not sa:
            continue
        # Prefer trust-validated IRSA edges; fall back to annotation-only.
        candidates: list[tuple[bool, str]] = []
        for edge in graph.edges:
            if edge.src_id != sa_id or edge.rel_type != "PROJECTS_TO":
                continue
            if str(edge.props.get("binding_type") or "") != "IRSA":
                continue
            validated = bool(edge.props.get("trust_validated"))
            candidates.append((validated, edge.dst_id))
        candidates.sort(key=lambda item: (0 if item[0] else 1, item[1]))
        chosen = [dst for ok, dst in candidates if ok] or [dst for _, dst in candidates]
        for role_id in chosen:
            sa_native = str(sa.props.get("native_id") or sa_id)
            added = _upsert_unlock(
                builder,
                graph,
                material_node_id,
                unlock_rel,
                role_id,
                enrichment_edge_props(
                    source="collector",
                    material_kind="k8s_service_account_token",
                    locator=locator,
                    mechanism="AssumeRoleWithWebIdentity",
                    via_sa=sa_native,
                    binding_type="IRSA",
                    trust_validated=any(ok for ok, dst in candidates if dst == role_id),
                    collector=collector,
                    confidence="inferred",
                    match="irsa-web-identity",
                ),
            )
            if added:
                stats["unlocks_applied"] += 1
            if role_id not in role_ids:
                role_ids.append(role_id)
    stats["role_ids"] = role_ids
    return stats


def repair_credential_impact(
    builder: GraphBuilder,
    *,
    declared_resources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Re-wire materials with typed impact_targets (session / blast repair)."""
    _ = declared_resources
    graph = builder.snapshot
    stats = {
        "materials": 0,
        "unlocks_applied": 0,
        "projected": 0,
        "pruned": 0,
        "junk_projected_removed": 0,
        "secret_scope_unlocks": 0,
    }
    stats["junk_projected_removed"] = _remove_junk_projected_targets(graph)

    for node_id, node in list(graph.nodes.items()):
        kind = str(node.props.get("material_kind") or "")
        if node.props.get("native_kind") != "PivotMaterial" and not kind:
            continue
        raw_targets = node.props.get("impact_targets")
        targets = _coerce_impact_target_rows(raw_targets)
        # Rebuild SA impact from JWT claims stored on the material when missing.
        if not targets and kind == "k8s_service_account_token":
            evidence = _coerce_evidence(node.props.get("evidence"))
            sub = str(evidence.get("jwt_sub") or "")
            if sub.startswith("system:serviceaccount:"):
                parts = sub.split(":")
                if len(parts) >= 4:
                    targets = [{"kind": "k8s_service_account", "name": f"{parts[2]}:{parts[3]}"}]
            elif evidence.get("k8s_namespace") and evidence.get("k8s_service_account"):
                targets = [
                    {
                        "kind": "k8s_service_account",
                        "name": f"{evidence['k8s_namespace']}:{evidence['k8s_service_account']}",
                    }
                ]
        if not targets:
            continue
        result = wire_credential_impact(
            builder,
            graph,
            material_node_id=node_id,
            material_kind=kind or "generic_credential_file",
            locator=str(node.props.get("locator") or ""),
            name_hints=_coerce_str_list(node.props.get("name_hints")),
            impact_targets=targets,
            evidence=_coerce_evidence(node.props.get("evidence")),
            collector=str(node.props.get("collector") or "collector"),
        )
        stats["materials"] += 1
        stats["unlocks_applied"] += int(result["unlocks_applied"])
        stats["projected"] += int(result["projected"])
        stats["pruned"] += int(result.get("pruned") or 0)

    scope = wire_secret_scope_unlocks(builder)
    stats["secret_scope_unlocks"] = int(scope.get("unlocks_applied") or 0)
    stats["unlocks_applied"] += stats["secret_scope_unlocks"]
    stats["pruned"] += int(scope.get("pruned") or 0)
    return stats


def wire_secret_scope_unlocks(builder: GraphBuilder) -> dict[str, Any]:
    """Secret:* (and inventored vaults) UNLOCKS typed targets when a material links them.

    Example: password material unlocks ``aws-goat-db`` and names ``RDS_CREDS`` →
    ``Secret:* -[UNLOCKS]-> aws-goat-db`` with ``where=RDS_CREDS``.
    Access to Secrets:* therefore reaches the DB without treating the vault label
    as the blast destination.
    """
    graph = builder.snapshot
    stats: dict[str, Any] = {"unlocks_applied": 0, "pruned": 0, "pairs": 0}
    desired: set[tuple[str, str, str]] = set()  # (src, dst, where)

    stubs = _secret_wildcard_nodes(graph)
    inventored = _inventored_secrets_by_name(graph)
    if not stubs and not inventored:
        stats["pruned"] = _prune_secret_scope_unlocks(graph, desired)
        return stats

    for _mat_id, mat in graph.nodes.items():
        if mat.props.get("native_kind") != "PivotMaterial" and not mat.props.get("material_kind"):
            continue
        targets = impact_targets_for_material(
            impact_targets=list(mat.props.get("impact_targets") or [])
        )
        if not targets:
            # Fall back to existing UNLOCKS destinations on the material.
            unlock_dsts = [
                e.dst_id
                for e in graph.edges
                if e.src_id == _mat_id and e.rel_type == "UNLOCKS"
            ]
            if not unlock_dsts:
                continue
        else:
            unlock_dsts = []
            for target in targets:
                unlock_dsts.append(
                    ensure_impact_target_node(
                        builder, graph, name=target["name"], kind=target["kind"]
                    )
                )

        wheres = _vault_names_for_material(mat.props, inventored)
        if not wheres:
            continue

        for where_name, vault_node_id in wheres:
            for dst_id in unlock_dsts:
                for stub_id in stubs:
                    desired.add((stub_id, dst_id, where_name))
                    if _upsert_unlock(
                        builder,
                        graph,
                        stub_id,
                        "UNLOCKS",
                        dst_id,
                        enrichment_edge_props(
                            source="collector",
                            match="credential-impact",
                            mechanism="secret-scope-yields-credential",
                            where=where_name,
                            via_secret=where_name,
                            secret_name=where_name,
                            store_kind=str(
                                (graph.nodes[dst_id].props.get("resource_type") if dst_id in graph.nodes else None)
                                or "db_instance"
                            ),
                            confidence="inferred",
                        ),
                    ):
                        stats["unlocks_applied"] += 1
                    stats["pairs"] += 1
                # Concrete vault also unlocks so capability-glob paths continue.
                if vault_node_id:
                    desired.add((vault_node_id, dst_id, where_name))
                    if _upsert_unlock(
                        builder,
                        graph,
                        vault_node_id,
                        "UNLOCKS",
                        dst_id,
                        enrichment_edge_props(
                            source="collector",
                            match="credential-impact",
                            mechanism="secret-store-yields-credential",
                            where=where_name,
                            via_secret=where_name,
                            secret_name=where_name,
                            store_kind=str(
                                (graph.nodes[dst_id].props.get("resource_type") if dst_id in graph.nodes else None)
                                or "db_instance"
                            ),
                            confidence="inferred",
                        ),
                    ):
                        stats["unlocks_applied"] += 1
                    stats["pairs"] += 1

    stats["pruned"] = _prune_secret_scope_unlocks(graph, desired)
    return stats


def _secret_wildcard_nodes(graph: GraphSnapshot) -> list[str]:
    """Policy stubs like ``Secret:*`` (not SSM/Lambda SecretStore collisions)."""
    out: list[str] = []
    for node_id, node in graph.nodes.items():
        native = str(node.props.get("native_id") or node_id)
        rtype = str(node.props.get("resource_type") or "")
        if "*" not in native and not native.endswith(":*"):
            continue
        if rtype == "Secret" or native.startswith("Secret:"):
            out.append(node_id)
    return out


def _inventored_secrets_by_name(graph: GraphSnapshot) -> dict[str, str]:
    """Lowercased secret display name → node_id (concrete inventored only)."""
    out: dict[str, str] = {}
    for node_id, node in graph.nodes.items():
        if not _is_secret_store_node(node):
            continue
        native = str(node.props.get("native_id") or "")
        if "*" in native or native.endswith(":*"):
            continue
        if node.props.get("native_kind") == "PivotMaterial" or node.props.get("material_kind"):
            continue
        for key in ("name", "display_name", "secret_name"):
            val = node.props.get(key)
            if val:
                out[str(val).strip().lower()] = node_id
    return out


def _is_secret_store_node(node: Any) -> bool:
    concept = str(node.props.get("concept_type") or "")
    rtype = str(node.props.get("resource_type") or "")
    native = str(node.props.get("native_id") or "")
    return concept == "SecretStore" or rtype == "Secret" or native.startswith("Secret:")


def _vault_names_for_material(
    props: dict[str, Any],
    inventored: dict[str, str],
) -> list[tuple[str, str | None]]:
    """Secret vault names linked to this material.

    Prefer inventored SecretStore matches. Also keep collector name_hints that are
    not themselves impact targets (e.g. ``RDS_CREDS`` beside ``aws-goat-db``) so
    ``Secret:*`` can UNLOCKS the DB with ``where=`` even when enum missed the vault.
    """
    found: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    impact_names = {
        str(row.get("name") or "").strip().lower()
        for row in _coerce_impact_target_rows(props.get("impact_targets"))
        if row.get("name")
    }
    for hint in _coerce_str_list(props.get("name_hints")):
        name = str(hint or "").strip()
        if not name:
            continue
        key = name.lower()
        if key in seen or key in impact_names:
            continue
        seen.add(key)
        found.append((name, inventored.get(key)))
    for row in _coerce_impact_target_rows(props.get("impact_targets")):
        if str(row.get("kind") or "") != "secretsmanager_secret":
            continue
        name = str(row.get("name") or "").strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        found.append((name, inventored.get(name.lower())))
    return found


def _prune_secret_scope_unlocks(
    graph: GraphSnapshot,
    desired: set[tuple[str, str, str]],
) -> int:
    """Drop prior secret-scope UNLOCKS not in the recomputed set."""
    mechanisms = frozenset(
        {"secret-scope-yields-credential", "secret-store-yields-credential"}
    )
    keep: list = []
    removed = 0
    touched: set[str] = set()
    for edge in graph.edges:
        if edge.rel_type != "UNLOCKS" or edge.props.get("mechanism") not in mechanisms:
            keep.append(edge)
            continue
        where = str(
            edge.props.get("where")
            or edge.props.get("via_secret")
            or edge.props.get("secret_name")
            or ""
        )
        key = (edge.src_id, edge.dst_id, where)
        # Also accept match without exact where casing.
        alt = (edge.src_id, edge.dst_id, where.lower())
        desired_norm = {(a, b, c.lower() if c else c) for a, b, c in desired}
        if key in desired or alt in desired_norm:
            keep.append(edge)
            continue
        removed += 1
        touched.add(edge.src_id)
    if removed:
        graph.edges[:] = keep
        if hasattr(graph, "adjacency"):
            for src in touched:
                graph.adjacency[src] = [
                    (e.dst_id, e.rel_type, e.props)
                    for e in graph.edges
                    if e.src_id == src
                ]
    return removed


def _secret_store_names(graph: GraphSnapshot) -> set[str]:
    """Lowercased display names of inventored SecretStore nodes."""
    names: set[str] = set()
    for node in graph.nodes.values():
        concept = str(node.props.get("concept_type") or "")
        rtype = str(node.props.get("resource_type") or "")
        native = str(node.props.get("native_id") or "")
        if concept != "SecretStore" and rtype != "Secret" and not native.startswith("Secret:"):
            continue
        if node.props.get("projected"):
            continue
        for key in ("name", "display_name"):
            val = node.props.get(key)
            if val:
                names.add(str(val).strip().lower())
    return names


def _remove_junk_projected_targets(graph: GraphSnapshot) -> int:
    """Drop projected impact nodes whose name collides with an inventored SecretStore."""
    secret_names = _secret_store_names(graph)
    projectable_types = {spec.resource_type for spec in IMPACT_KIND_REGISTRY.values()} | {
        "Rds",
        "RDS",
        "DBInstance",
    }
    remove: list[str] = []
    for node_id, node in list(graph.nodes.items()):
        if not node.props.get("projected"):
            continue
        rtype = str(node.props.get("resource_type") or "")
        reason = str(node.props.get("projected_reason") or "")
        if reason not in {"credential-impact", ""} and rtype not in projectable_types:
            continue
        if rtype and rtype not in projectable_types and reason != "credential-impact":
            continue
        name = str(
            node.props.get("db_instance_identifier")
            or node.props.get("bucket_name")
            or node.props.get("name")
            or node.props.get("display_name")
            or ""
        ).strip().lower()
        if name and name in secret_names:
            remove.append(node_id)
    for node_id in remove:
        graph.remove_node(node_id)
    return len(remove)


def _prune_stale_unlocks(
    graph: GraphSnapshot,
    material_node_id: str,
    desired: set[str],
) -> int:
    """Drop this material's UNLOCKS that are not in the current typed target set."""
    keep: list = []
    removed = 0
    for edge in graph.edges:
        if edge.src_id != material_node_id or edge.rel_type != "UNLOCKS":
            keep.append(edge)
            continue
        if edge.dst_id in desired:
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


def _is_concrete_target(graph: GraphSnapshot, node_id: str, kind: str) -> bool:
    """True when node matches the registered impact kind shape."""
    spec = get_impact_kind(kind)
    if not spec:
        return False
    node = graph.nodes.get(node_id)
    if not node:
        return False
    if node.props.get("native_kind") == "PivotMaterial" or node.props.get("material_kind"):
        return False

    concept = str(node.props.get("concept_type") or "")
    rtype = str(node.props.get("resource_type") or node.props.get("native_kind") or "")
    native = str(node.props.get("native_id") or "")

    # Never treat an inventored secret vault as a db_instance (or other non-secret kinds).
    if kind != "secretsmanager_secret":
        if concept == "SecretStore" or rtype == "Secret" or native.startswith("Secret:"):
            return False

    if rtype == spec.resource_type or native.startswith(f"{spec.resource_type}:"):
        return True
    if kind == "k8s_service_account":
        if native.startswith("kubernetes:serviceaccount:"):
            return True
        if rtype == "ServiceAccount" or node.props.get("native_kind") == "ServiceAccount":
            return True
    if kind == "db_instance":
        if rtype in {"RDSInstance", "Rds", "RDS", "DBInstance"}:
            return True
        if native.startswith(("RDSInstance:", "Rds:", "DBInstance:")):
            return True
        if concept == "DataStore":
            low = rtype.lower()
            return any(tok in low for tok in ("rds", "db", "database", "aurora"))
    if concept == spec.concept.value:
        return True
    return False


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
