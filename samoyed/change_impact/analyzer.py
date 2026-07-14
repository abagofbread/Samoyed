from __future__ import annotations

from typing import Any

from samoyed.attack.analyzer import analyze_attack_surface, apply_attack_analysis
from samoyed.attack.surface import enrich_attack_surface
from samoyed.change_impact.applier import apply_changes
from samoyed.change_impact.models import ChangeImpactResult, Finding, ProposedChange
from samoyed.cloud.concepts import CloudProvider
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.snapshot import copy_snapshot
from samoyed.path_engine.search import find_attack_paths, get_blast_radius
from samoyed.policy.access import (
    can_principal_access_node,
    find_internet_write_exposures,
    find_isolation_breaches,
    principal_has_crypto_mining_risk,
)


SIGNIFICANT_SEVERITIES = frozenset({"critical", "high"})


def analyze_proposed_changes(
    graph,
    changes: list[ProposedChange | dict[str, Any]],
    *,
    provider: CloudProvider = CloudProvider.AWS,
    context_principal: str | None = None,
    max_depth: int = 8,
) -> ChangeImpactResult:
    parsed = [c if isinstance(c, ProposedChange) else ProposedChange.from_dict(c) for c in changes]
    before = _snapshot_metrics(graph, provider=provider, context_principal=context_principal, max_depth=max_depth)

    after_graph = copy_snapshot(graph)
    applied = apply_changes(after_graph, parsed)
    after_builder = GraphBuilder(after_graph.session_id)
    after_builder.snapshot = after_graph
    enrich_attack_surface(after_builder)
    apply_attack_analysis(after_builder, provider=provider)

    after = _snapshot_metrics(
        after_builder.snapshot,
        provider=provider,
        context_principal=context_principal,
        max_depth=max_depth,
    )
    findings = _diff_findings(before, after, parsed, context_principal=context_principal)
    significant = any(f.severity in SIGNIFICANT_SEVERITIES for f in findings)
    return ChangeImpactResult(
        significant=significant,
        findings=findings,
        before=before,
        after=after,
        changes_applied=applied,
    )


def _snapshot_metrics(
    graph,
    *,
    provider: CloudProvider,
    context_principal: str | None,
    max_depth: int,
) -> dict[str, Any]:
    privesc_edges = analyze_attack_surface(graph, provider=provider)
    exposures = find_internet_write_exposures(graph)
    breaches = find_isolation_breaches(graph, max_depth=max_depth)
    mining: dict[str, Any] | None = None
    if context_principal:
        mining = principal_has_crypto_mining_risk(graph, context_principal)

    caller_paths = 0
    if context_principal:
        from samoyed.graph.refs import resolve_node_ref

        start = resolve_node_ref(graph, context_principal)
        if start:
            caller_paths = len(get_blast_radius(graph, start_node_id=start, max_depth=max_depth))

    ssrf_nodes = [
        nid
        for nid, node in graph.nodes.items()
        if node.props.get("ssrf_vulnerable")
    ]

    return {
        "privesc_patterns": len(privesc_edges),
        "internet_write_exposures": len(exposures),
        "isolation_breaches": len(breaches),
        "crypto_mining_at_risk": bool(mining and mining.get("at_risk")),
        "caller_blast_reach": caller_paths,
        "ssrf_vulnerable_compute": len(ssrf_nodes),
        "exposures": exposures,
        "breaches": breaches,
        "mining": mining,
    }


def _diff_findings(
    before: dict[str, Any],
    after: dict[str, Any],
    changes: list[ProposedChange],
    *,
    context_principal: str | None,
) -> list[Finding]:
    findings: list[Finding] = []

    if after["privesc_patterns"] > before["privesc_patterns"]:
        findings.append(
            Finding(
                severity="critical",
                category="privesc_introduced",
                title="New privilege-escalation patterns detected",
                description=(
                    f"Proposed changes introduce {after['privesc_patterns'] - before['privesc_patterns']} "
                    "new attack pattern(s) that were not present before."
                ),
                evidence={
                    "before": before["privesc_patterns"],
                    "after": after["privesc_patterns"],
                },
            )
        )

    new_exposures = [
        e for e in after["exposures"]
        if e["node_id"] not in {x["node_id"] for x in before["exposures"]}
    ]
    for exposure in new_exposures:
        findings.append(
            Finding(
                severity="critical",
                category="exposure_opened",
                title="Internet write exposure introduced",
                description=(
                    f"{exposure['display_name']} would be writable from the public internet."
                ),
                evidence=exposure,
            )
        )

    new_breaches = [
        b for b in after["breaches"]
        if (b["from"], b["to"]) not in {(x["from"], x["to"]) for x in before["breaches"]}
    ]
    for breach in new_breaches:
        findings.append(
            Finding(
                severity="critical",
                category="isolation_breach",
                title="Sensitive environment isolation breach",
                description=(
                    f"Internet-exposed {breach['from_exposure']} could reach "
                    f"isolated target ({breach['to_sensitivity']}) in {breach['hops']} hop(s)."
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
                    title="Principal could launch unrestricted compute",
                    description=(
                        "The proposed change would let this principal launch EC2 instances with "
                        "PassRole or wildcard permissions — a common crypto-mining abuse pattern."
                    ),
                    evidence=after_mining,
                )
            )

    for change in changes:
        if change.type in {"grant_action", "add_edge", "add_trust"} and change.principal and change.target:
            _append_access_findings(findings, change)

    if not findings:
        findings.append(
            Finding(
                severity="info",
                category="policy_access_granted",
                title="No significant new risks detected",
                description="Samoyed did not find new critical exposures, isolation breaches, or privesc patterns.",
                evidence={"changes": len(changes)},
            )
        )

    return findings


def _append_access_findings(findings: list[Finding], change: ProposedChange) -> None:
    action = change.action or change.rel or "access"
    findings.append(
        Finding(
            severity="medium",
            category="policy_access_granted",
            title="Proposed access grant",
            description=(
                f"Change would grant {action} from {change.principal} to {change.target}."
            ),
            evidence=change.__dict__,
        )
    )
