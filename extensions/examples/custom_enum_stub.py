"""Example custom enumerator — see AGENTS.md."""

from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext


class CustomEnumStubEnumerator:
    concept = ConceptType.IDENTITY
    name = "custom-enum-stub"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id="custom:example",
            scope_id=ctx.scope.scope_id,
            properties={"native_kind": "Custom"},
            evidence=Evidence("example", {"note": "reference implementation"}),
            confidence=ConfidenceType.EXPLICIT,
        )
