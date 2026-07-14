from __future__ import annotations

from typing import Any

from samoyed.attack.analyzer import analyze_attack_surface
from samoyed.change_impact.models import Finding, GraphCompareResult
from samoyed.cloud.concepts import CloudProvider
from samoyed.graph.identity import display_for_id, stable_key_for_id
from samoyed.graph.markings import find_compromised_nodes, find_high_value_nodes
from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.search import (
    find_attack_paths_from_sources,
    find_compromised_to_high_value_paths,
    get_blast_radius_multi,
)
from samoyed.policy.access import (
    find_internet_write_exposures,
    find_isolation_breaches,
    principal_has_crypto_mining_risk,
)

SIGNIFICANT_SEVERITIES = frozenset({"critical", "high"})

TARGET_CONCEPTS = ("SecretStore", "DataStore", "AttackOutcome")


def compare_attack_surfaces(
    baseline: GraphSnapshot,
    proposed: GraphSnapshot,
    *,
    provider: CloudProvider = CloudProvider.AWS,
    context_principal: str | None = None,
    max_depth: int = 10,
    max_paths: int = 40,
) -> GraphCompareResult:
    """Diff attack surface between canon (baseline) and PR (proposed) graphs."""
    before = _collect_surface(baseline, provider=provider, context_principal=context_principal, max_depth=max_depth, max_paths=max_paths)
    after = _collect_surface(proposed, provider=provider, context_principal=context_principal, max_depth=max_depth, max_paths=max_paths)

    new_paths = _diff_path_signatures(before["path_signatures"], after["path_signatures"])
    findings = _diff_surface_findings(before, after, new_paths, context_principal=context_principal)

    if not findings and not new_paths:
        findings.append(
            Finding(
                severity="info",
                category="new_attack_path",
                title="No new attack paths detected",
                description="Proposed graph does not introduce attack paths beyond the baseline canon.",
                evidence={"baseline_paths": len(before["path_signatures"]), "proposed_paths": len(after["path_signatures"])},
            )
        )

    significant = any(f.severity in SIGNIFICANT_SEVERITIES for f in findings) or bool(new_paths)
    return GraphCompareResult(
        significant=significant,
        findings=findings,
        new_paths=new_paths[:max_paths],
        baseline_summary=_summary_from_surface(before),
        proposed_summary=_summary_from_surface(after),
        baseline_session_id=baseline.session_id,
        proposed_session_id=proposed.session_id,
    )


def _collect_surface(
    graph: GraphSnapshot,
    *,
    provider: CloudProvider,
    context_principal: str | None,
    max_depth: int,
    max_paths: int,
) -> dict[str, Any]:
    starts = _attack_starts(graph, context_principal)
    paths: list[Any] = []

    if find_compromised_nodes(graph) and find_high_value_nodes(graph):
        paths.extend(
            find_compromised_to_high_value_paths(graph, max_depth=max_depth, max_paths=max_paths // 2)
        )

    for concept in TARGET_CONCEPTS:
        paths.extend(
            find_attack_paths_from_sources(
                graph,
                start_node_ids=starts,
                target_concept=concept,
                max_depth=max_depth,
                max_paths=max(5, max_paths // len(TARGET_CONCEPTS)),
            )
        )

    paths.extend(
        get_blast_radius_multi(
            graph,
            start_node_ids=starts,
            max_depth=max_depth,
            max_paths=max_paths // 2,
        )
    )

    path_signatures = _path_signatures(graph, paths)
    privesc = _privesc_signatures(graph, provider)
    exposures = find_internet_write_exposures(graph)
    breaches = find_isolation_breaches(graph, max_depth=max_depth)

    mining = None
    if context_principal:
        from samoyed.graph.refs import resolve_node_ref

        ref = resolve_node_ref(graph, context_principal)
        if ref:
            mining = principal_has_crypto_mining_risk(graph, ref)

    return {
        "path_signatures": path_signatures,
        "privesc_signatures": privesc,
        "exposures": exposures,
        "breaches": breaches,
        "mining": mining,
        "privesc_count": len(privesc),
        "path_count": len(path_signatures),
    }


def _attack_starts(graph: GraphSnapshot, context_principal: str | None) -> list[str]:
    from samoyed.graph.refs import resolve_node_ref

    starts: list[str] = []
    if context_principal:
        resolved = resolve_node_ref(graph, context_principal)
        if resolved:
            starts.append(resolved)

    for node_id, node in graph.nodes.items():
        if node.label == "CollectionSession":
            continue
        if node.props.get("is_caller") or node.props.get("is_scenario_start"):
            if node_id not in starts:
                starts.append(node_id)

    compromised = find_compromised_nodes(graph)
    for node_id in compromised:
        if node_id not in starts:
            starts.append(node_id)

    return starts or list(graph.nodes.keys())[:1]


def _path_signatures(graph: GraphSnapshot, paths: list[Any]) -> dict[str, dict[str, Any]]:
    signatures: dict[str, dict[str, Any]] = {}
    for path in paths:
        if len(path.node_ids) < 2:
            continue
        start_key = stable_key_for_id(graph, path.node_ids[0])
        end_key = stable_key_for_id(graph, path.node_ids[-1])
        rels = tuple(s.rel_type for s in path.steps)
        sig = f"{start_key}|{end_key}|{'/'.join(rels)}"
        if sig in signatures:
            continue
        signatures[sig] = {
            "signature": sig,
            "start": start_key,
            "start_display": display_for_id(graph, path.node_ids[0]),
            "target": end_key,
            "target_display": display_for_id(graph, path.node_ids[-1]),
            "hops": len(path.steps),
            "rels": list(rels),
            "score": path.score,
            "target_match": path.target_match,
        }
    return signatures


def _privesc_signatures(graph: GraphSnapshot, provider: CloudProvider) -> set[str]:
    edges = analyze_attack_surface(graph, provider=provider)
    out: set[str] = set()
    for edge in edges:
        src = stable_key_for_id(graph, edge.src_id)
        dst = stable_key_for_id(graph, edge.dst_id)
        pattern = edge.pattern.id
        out.add(f"{src}|{pattern}|{dst}")
    return out


def _diff_path_signatures(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    new_sigs = set(after) - set(before)
    ranked = sorted(
        (after[sig] for sig in new_sigs),
        key=lambda p: (-p.get("score", 0), p.get("hops", 0)),
    )
    return ranked


def _diff_surface_findings(
    before: dict[str, Any],
    after: dict[str, Any],
    new_paths: list[dict[str, Any]],
    *,
    context_principal: str | None,
) -> list[Finding]:
    findings: list[Finding] = []

    for path in new_paths[:15]:
        findings.append(
            Finding(
                severity="critical" if path.get("hops", 99) <= 6 else "high",
                category="new_attack_path",
                title="New attack path in proposed graph",
                description=(
                    f"{path['start_display']} can reach {path['target_display']} "
                    f"via {' → '.join(path['rels'])} ({path['hops']} hop(s))."
                ),
                evidence=path,
            )
        )

    new_privesc = after["privesc_signatures"] - before["privesc_signatures"]
    if new_privesc:
        findings.append(
            Finding(
                severity="critical",
                category="privesc_introduced",
                title="New privilege-escalation patterns in proposed graph",
                description=f"{len(new_privesc)} new privesc pattern(s) not present in baseline.",
                evidence={"patterns": sorted(new_privesc)[:20]},
            )
        )

    new_exposures = [
        e for e in after["exposures"]
        if stable_exposure_key(e) not in {stable_exposure_key(x) for x in before["exposures"]}
    ]
    for exposure in new_exposures:
        findings.append(
            Finding(
                severity="critical",
                category="exposure_opened",
                title="New internet write exposure",
                description=f"{exposure['display_name']} is writable from the public internet in the proposed graph.",
                evidence=exposure,
            )
        )

    before_breach_keys = {_breach_key(b) for b in before["breaches"]}
    for breach in after["breaches"]:
        if _breach_key(breach) in before_breach_keys:
            continue
        findings.append(
            Finding(
                severity="critical",
                category="isolation_breach",
                title="New environment isolation breach",
                description=(
                    f"{breach.get('from_exposure', breach['from'])} can reach "
                    f"{breach.get('to_sensitivity', breach['to'])} in {breach['hops']} hop(s)."
                ),
                evidence=breach,
            )
        )

    if context_principal:
        before_mining = before.get("mining") or {}
        after_mining = after.get("mining") or {}
        if not before_mining.get("at_risk") and after_mining.get("at_risk"):
            findings.append(
                Finding(
                    severity="high",
                    category="mining_risk",
                    title="Principal gains unrestricted compute launch",
                    description=(
                        "Proposed graph would let this principal launch EC2 with PassRole or wildcard — "
                        "common crypto-mining abuse."
                    ),
                    evidence=after_mining,
                )
            )

    return findings


def stable_exposure_key(exposure: dict[str, Any]) -> str:
    return str(exposure.get("display_name") or exposure.get("node_id") or "")


def _breach_key(breach: dict[str, Any]) -> tuple[str, str]:
    return (str(breach.get("from")), str(breach.get("to")))


def _summary_from_surface(surface: dict[str, Any]) -> dict[str, Any]:
    return {
        "attack_path_signatures": surface["path_count"],
        "privesc_patterns": surface["privesc_count"],
        "internet_write_exposures": len(surface["exposures"]),
        "isolation_breaches": len(surface["breaches"]),
        "crypto_mining_at_risk": bool(surface.get("mining") and surface["mining"].get("at_risk")),
    }
