from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
FindingCategory = Literal[
    "new_attack_path",
    "exposure_opened",
    "isolation_breach",
    "mining_risk",
    "policy_access_granted",
    "privesc_introduced",
    "compute_compromise",
]


@dataclass
class ProposedChange:
    """A single hypothetical IAM, network, or resource change."""

    type: str
    principal: str | None = None
    target: str | None = None
    action: str | None = None
    rel: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProposedChange":
        excluded = {
            "type",
            "change_type",
            "principal",
            "from",
            "target",
            "to",
            "resource",
            "action",
            "rel",
            "relationship",
            "properties",
        }
        properties = dict(data.get("properties") or {})
        for key, value in data.items():
            if key not in excluded:
                properties[key] = value
        return cls(
            type=str(data.get("type") or data.get("change_type") or ""),
            principal=data.get("principal") or data.get("from"),
            target=data.get("target") or data.get("to") or data.get("resource"),
            action=data.get("action"),
            rel=data.get("rel") or data.get("relationship"),
            properties=properties,
        )


@dataclass
class Finding:
    severity: FindingSeverity
    category: FindingCategory
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChangeImpactResult:
    significant: bool
    findings: list[Finding]
    before: dict[str, Any]
    after: dict[str, Any]
    changes_applied: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "significant": self.significant,
            "findings": [_finding_dict(f) for f in self.findings],
            "before": self.before,
            "after": self.after,
            "changes_applied": self.changes_applied,
        }


GraphAccessLevel = Literal["full", "summary", "compare_only"]
GraphRole = Literal["canon", "proposed", "interactive", "ephemeral"]


@dataclass
class GraphCompareResult:
    significant: bool
    findings: list[Finding]
    new_paths: list[dict[str, Any]]
    baseline_summary: dict[str, Any]
    proposed_summary: dict[str, Any]
    baseline_session_id: str
    proposed_session_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "significant": self.significant,
            "findings": [_finding_dict(f) for f in self.findings],
            "new_paths": self.new_paths,
            "baseline_summary": self.baseline_summary,
            "proposed_summary": self.proposed_summary,
            "baseline_session_id": self.baseline_session_id,
            "proposed_session_id": self.proposed_session_id,
        }


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "severity": finding.severity,
        "category": finding.category,
        "title": finding.title,
        "description": finding.description,
        "evidence": finding.evidence,
    }
