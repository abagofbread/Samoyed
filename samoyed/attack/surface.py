from __future__ import annotations

from typing import Any

from samoyed.attack.capability_bindings import enrich_capability_bindings
from samoyed.attack.k8s_pivot import enrich_k8s_deploy_pivot
from samoyed.attack.high_value import enrich_high_value_targets
from samoyed.attack.passrole_ec2 import enrich_passrole_ec2_bindings
from samoyed.attack.resource_pivot import enrich_resource_pivots
from samoyed.attack.service_admin import enrich_service_admins
from samoyed.attack.shared_env import enrich_shared_environments
from samoyed.attack.shadow_admin import enrich_shadow_admins
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder, stable_id
from samoyed.graph.dedupe import dedupe_redundant_edges
from samoyed.graph.enrichment import mark_enrichment_edges
from samoyed.graph.markings import COMPROMISE_MECHANISM
from samoyed.graph.model import GraphSnapshot

COMPUTE_RESOURCE_TYPES = frozenset(
    {
        "LambdaFunction",
        "EC2Instance",
        "ECSTask",
        "ECSService",
        "CloudFunction",
        "CodeBuildProject",
        "CodePipeline",
    }
)

# ECS task/container identity comes from 169.254.170.2, not classic IMDS.
# Host IMDS is modeled on the RUNS_ON EC2Instance after container escape.
_SKIP_IMDS_RESOURCE_TYPES = frozenset(
    {
        "LambdaFunction",
        "ECSTask",
        "ECSContainer",
        "ECSService",
        "ECSEscape",
    }
)

IMDS_NATIVE_ID = "aws:imds:instance-metadata"
INTERNET_EXPOSURE_NATIVE_ID = "network:internet"
# Display name for the shared internet exposure node (also used by network enrichment).
INTERNET_DISPLAY_NAME = "The Internet"


def _imds_native_id(compute_id: str, node: Any) -> str:
    """Per-workload metadata surface — IMDS creds are local to one instance/function."""
    instance_id = node.props.get("instance_id")
    if instance_id:
        return f"{IMDS_NATIVE_ID}:{instance_id}"
    native = node.props.get("native_id") or compute_id
    return f"{IMDS_NATIVE_ID}:{native}"


def _ensure_imds_node(builder: GraphBuilder, graph: GraphSnapshot, compute_id: str, node: Any) -> str:
    native_id = _imds_native_id(compute_id, node)
    existing = stable_id("EscapeSurface", native_id)
    if existing in graph.nodes:
        return existing
    label = node.props.get("name") or node.props.get("display_name") or compute_id
    return builder.add_concept_node(
        concept_type=ConceptType.ESCAPE_SURFACE,
        native_id=native_id,
        props={
            "display_name": f"Instance metadata (IMDS) — {label}",
            "resource_type": "IMDS",
            "provider": "aws",
            "source": "surface-enrichment",
            "bound_compute": compute_id,
            "instance_id": node.props.get("instance_id"),
        },
    )


def enrich_attack_surface(
    builder: GraphBuilder,
    *,
    provider: CloudProvider | None = None,
) -> dict[str, int]:
    """Add compute escape surfaces and network exposure edges to the graph."""
    graph = builder.snapshot
    stats = {
        "imds_surfaces": _wire_imds_surfaces(builder, graph),
        "ssrf_chains": _wire_ssrf_chains(builder, graph),
        "network_exposures": _wire_network_exposure(builder, graph),
        "scope_hosting": _wire_scope_hosting(builder, graph),
    }
    stats.update(enrich_k8s_deploy_pivot(builder))
    # OIDC trust Conditions → SA PROJECTS_TO (before token UNLOCKS / capability-glob).
    from samoyed.attack.irsa_trust import enrich_irsa_trust

    stats.update(enrich_irsa_trust(builder))
    # Materials + Secret:* UNLOCKS before capability-glob so vaults that yield
    # credentials (RDS_CREDS → aws-goat-db) are eligible for CONTROLS expansion.
    from samoyed.enrichment.impact import repair_credential_impact

    impact = repair_credential_impact(builder)
    stats["credential_unlocks"] = int(impact.get("unlocks_applied") or 0)
    stats["credential_projected"] = int(impact.get("projected") or 0)
    stats["secret_scope_unlocks"] = int(impact.get("secret_scope_unlocks") or 0)
    # Bind policy Resource globs to inventored assets before FEEDS intersection.
    stats.update(enrich_capability_bindings(builder))
    # PassRole+RunInstances → inventored EC2s that already EXECUTES_AS the passed role.
    stats.update(enrich_passrole_ec2_bindings(builder))
    stats.update(enrich_resource_pivots(builder))
    stats.update(enrich_shared_environments(builder))
    stats.update(enrich_high_value_targets(builder, provider=provider))
    stats.update(enrich_service_admins(builder, provider=provider))
    # After standing admins are marked, detect principals that can reach them.
    stats.update(enrich_shadow_admins(builder, provider=provider))
    # After privesc + trust are both present, drop weaker duplicate pivots.
    stats.update(dedupe_redundant_edges(builder))
    stats["enrichment_edges_marked"] = mark_enrichment_edges(builder.snapshot)
    return stats


def repair_blast_graph(builder: GraphBuilder) -> dict[str, int]:
    """Lazy influence wiring before blast: capability-glob, UNLOCKS, FEEDS.

    No new edge types — ensures CONTROLS/WRITES globs, credential UNLOCKS, and
    FEEDS exist so blast can reach named nodes without a separate enrich click.
    """
    from samoyed.attack.irsa_trust import enrich_irsa_trust
    from samoyed.enrichment.impact import repair_credential_impact

    stats: dict[str, int] = {}
    stats.update(enrich_irsa_trust(builder))
    # Materials + Secret:* → named targets first so capability-glob can bind
    # inventored vaults that UNLOCKS impact (e.g. RDS_CREDS → aws-goat-db).
    impact = repair_credential_impact(builder)
    stats["credential_unlocks"] = int(impact.get("unlocks_applied") or 0)
    stats["credential_projected"] = int(impact.get("projected") or 0)
    stats["junk_projected_removed"] = int(impact.get("junk_projected_removed") or 0)
    stats["secret_scope_unlocks"] = int(impact.get("secret_scope_unlocks") or 0)
    stats.update(enrich_capability_bindings(builder))
    stats.update(enrich_resource_pivots(builder))
    return stats


def blast_graph_changed(stats: dict[str, int]) -> bool:
    """True when lazy blast repair mutated the graph enough to persist."""
    return any(
        int(stats.get(key) or 0) > 0
        for key in (
            "capability_bindings",
            "unused_secret_bindings_pruned",
            "credential_unlocks",
            "credential_projected",
            "junk_projected_removed",
            "secret_scope_unlocks",
            "feeds_edges",
            "irsa_projects_to",
            "irsa_validated_stamped",
            "irsa_sa_projected",
        )
    )


def _wire_imds_surfaces(builder: GraphBuilder, graph: GraphSnapshot) -> int:
    added = 0
    for node_id, node in list(graph.nodes.items()):
        rtype = node.props.get("resource_type")
        concept = node.props.get("concept_type")
        if concept not in {"RuntimeBinding", "Workload"} and rtype not in COMPUTE_RESOURCE_TYPES:
            continue
        if rtype in _SKIP_IMDS_RESOURCE_TYPES or node.props.get("native_kind") == "ECSContainer":
            continue
        role_id = _execution_role_for_compute(graph, node_id)
        if not role_id:
            continue
        imds_id = _ensure_imds_node(builder, graph, node_id, node)
        key = (node_id, "CAN_ESCAPE_TO", imds_id)
        if not _has_edge(graph, *key):
            builder.add_edge(
                src_id=node_id,
                rel_type="CAN_ESCAPE_TO",
                dst_id=imds_id,
                props={
                    "source": "surface-enrichment",
                    "mechanism": "imds",
                    "confidence": "explicit",
                },
            )
            added += 1
        if not _has_edge(graph, imds_id, "EXECUTES_AS", role_id):
            builder.add_edge(
                src_id=imds_id,
                rel_type="EXECUTES_AS",
                dst_id=role_id,
                props={
                    "source": "surface-enrichment",
                    "mechanism": "imds-credential-theft",
                    "confidence": "explicit",
                    "bound_compute": node_id,
                },
            )
            added += 1
    return added


def _is_ssrf_hypothesis(props: dict[str, Any]) -> bool:
    """Lab oracle flag or analyst mechanism — substrate (IMDS+role) is the real story."""
    if props.get("ssrf_vulnerable"):
        return True
    mech = str(props.get(COMPROMISE_MECHANISM) or props.get("mechanism") or "").lower()
    return mech in {"ssrf", "ssrf-to-imds", "server-side-request-forgery"}


def _wire_ssrf_chains(builder: GraphBuilder, graph: GraphSnapshot) -> int:
    added = 0
    for node_id, node in list(graph.nodes.items()):
        if not _is_ssrf_hypothesis(node.props):
            continue
        # Normalize lab flag into mechanism without forcing compromised.
        if node.props.get("ssrf_vulnerable") and not node.props.get(COMPROMISE_MECHANISM):
            node.props[COMPROMISE_MECHANISM] = "ssrf"
        role_id = _execution_role_for_compute(graph, node_id)
        if not role_id:
            continue
        imds_id = _ensure_imds_node(builder, graph, node_id, node)
        if not _has_edge(graph, node_id, "CAN_ESCAPE_TO", imds_id):
            builder.add_edge(
                src_id=node_id,
                rel_type="CAN_ESCAPE_TO",
                dst_id=imds_id,
                props={
                    "source": "surface-enrichment",
                    "mechanism": "ssrf-to-imds",
                    "pattern_id": "aws-ssrf-imds",
                    "pattern_name": "SSRF to instance metadata",
                    "severity": "critical",
                    "confidence": "explicit",
                },
            )
            added += 1
        if not _has_edge(graph, imds_id, "EXECUTES_AS", role_id):
            builder.add_edge(
                src_id=imds_id,
                rel_type="EXECUTES_AS",
                dst_id=role_id,
                props={
                    "source": "surface-enrichment",
                    "mechanism": "ssrf-metadata-creds",
                    "confidence": "explicit",
                    "bound_compute": node_id,
                },
            )
            added += 1
    return added


def _wire_network_exposure(builder: GraphBuilder, graph: GraphSnapshot) -> int:
    """Connect internet-exposed resources to a single shared 'The Internet' node.

    Lightweight model: 'The Internet -CAN_REACH-> resource' directly. We do NOT
    create per-resource intermediate exposure nodes, and we never treat the
    Internet node (or any NetworkExposure node) as an exposable resource — doing
    so previously produced 'internet exposure for The Internet' and an unbounded
    'internet exposure for internet exposure for ...' feedback loop on re-enrichment.
    """
    internet_id = builder.add_concept_node(
        concept_type=ConceptType.NETWORK_EXPOSURE,
        native_id=INTERNET_EXPOSURE_NATIVE_ID,
        props={
            "display_name": INTERNET_DISPLAY_NAME,
            "exposure_level": "internet",
            "resource_type": "NetworkExposure",
            "source": "surface-enrichment",
        },
    )
    added = 0
    for node_id, node in list(graph.nodes.items()):
        if node_id == internet_id:
            continue
        if _is_network_exposure_node(node):
            continue
        if _resource_exposure(node.props) != "internet":
            continue
        if _has_edge(graph, internet_id, "CAN_REACH", node_id):
            continue
        write_exposed = bool(node.props.get("public_write") or node.props.get("internet_write"))
        props = {
            "source": "surface-enrichment",
            "exposure_level": "internet",
            "confidence": "explicit",
        }
        if write_exposed:
            props["write_exposed"] = True
            props["severity"] = "critical"
        builder.add_edge(
            src_id=internet_id,
            rel_type="CAN_REACH",
            dst_id=node_id,
            props=props,
        )
        added += 1
    return added


def _is_network_exposure_node(node: Any) -> bool:
    return (
        node.props.get("resource_type") == "NetworkExposure"
        or node.props.get("concept_type") == ConceptType.NETWORK_EXPOSURE.value
    )


def _wire_scope_hosting(builder: GraphBuilder, graph: GraphSnapshot) -> int:
    scope_nodes: dict[str, str] = {}
    for node_id, node in list(graph.nodes.items()):
        if node.props.get("concept_type") != "ScopeBoundary":
            continue
        native = node.props.get("native_id") or node_id
        scope_nodes[native] = node_id
        if node.props.get("name"):
            scope_nodes[str(node.props["name"])] = node_id
        if node.props.get("environment"):
            scope_nodes[str(node.props["environment"])] = node_id

    added = 0
    for node_id, node in list(graph.nodes.items()):
        if node.props.get("concept_type") == "ScopeBoundary":
            continue
        scope_ref = (
            node.props.get("scope_boundary")
            or node.props.get("environment")
            or node.props.get("ou")
        )
        if not scope_ref:
            continue
        scope_id = scope_nodes.get(str(scope_ref))
        if not scope_id:
            scope_id = builder.add_concept_node(
                concept_type=ConceptType.SCOPE_BOUNDARY,
                native_id=str(scope_ref),
                props={
                    "display_name": str(scope_ref),
                    "environment": node.props.get("environment"),
                    "sensitivity": node.props.get("sensitivity"),
                    "source": "surface-enrichment",
                },
            )
            scope_nodes[str(scope_ref)] = scope_id
        if not _has_edge(graph, node_id, "HOSTED_IN", scope_id):
            builder.add_edge(
                src_id=node_id,
                rel_type="HOSTED_IN",
                dst_id=scope_id,
                props={"source": "surface-enrichment", "confidence": "explicit"},
            )
            added += 1
    return added


def _resource_exposure(props: dict[str, Any]) -> str | None:
    if props.get("public_write") or props.get("internet_write"):
        return "internet"
    if props.get("public_read") or props.get("internet_readable"):
        return "internet"
    if props.get("has_public_url") or props.get("publicly_accessible"):
        return "internet"
    if props.get("exposure_level"):
        return str(props["exposure_level"])
    if props.get("internal_only"):
        return "internal"
    return None


def _execution_role_for_compute(graph: GraphSnapshot, compute_id: str) -> str | None:
    for dst_id, rel, _props in graph.adjacency.get(compute_id, []):
        if rel == "EXECUTES_AS":
            return dst_id
    node = graph.nodes.get(compute_id)
    if not node:
        return None
    role_arn = node.props.get("execution_role_arn")
    if not role_arn:
        return None
    for nid, n in graph.nodes.items():
        if n.props.get("arn") == role_arn or n.props.get("native_id") == role_arn:
            return nid
    return None


def _has_edge(graph: GraphSnapshot, src: str, rel: str, dst: str) -> bool:
    for dst_id, edge_rel, _props in graph.adjacency.get(src, []):
        if edge_rel == rel and dst_id == dst:
            return True
    return False
