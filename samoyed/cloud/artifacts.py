from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .concepts import CloudProvider, ConceptType, ConfidenceType


@dataclass(frozen=True)
class Evidence:
    kind: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConceptEdge:
    rel_type: str
    target_native_id: str = ""
    target_concept_type: ConceptType | None = None
    target_label: str | None = None
    src_native_id: str | None = None  # if set, edge starts here instead of artifact node
    props: dict[str, Any] = field(default_factory=dict)
    confidence: ConfidenceType = ConfidenceType.EXPLICIT


@dataclass
class ConceptArtifact:
    concept_type: ConceptType
    provider: CloudProvider
    native_id: str
    scope_id: str
    properties: dict[str, Any] = field(default_factory=dict)
    evidence: Evidence | None = None
    confidence: ConfidenceType = ConfidenceType.EXPLICIT
    edges: list[ConceptEdge] = field(default_factory=list)
    raw_ref: str | None = None


@dataclass
class DenialRecord:
    provider: CloudProvider
    operation: str
    error_code: str
    message: str


@dataclass
class DenialLog:
    records: list[DenialRecord] = field(default_factory=list)

    def add(self, record: DenialRecord) -> None:
        self.records.append(record)
