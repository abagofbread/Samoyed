from __future__ import annotations

from typing import Iterator, Protocol

from samoyed.cloud.artifacts import ConceptArtifact
from samoyed.cloud.concepts import ConceptType
from samoyed.credentials.protocol import EnumContext


class ConceptEnumerator(Protocol):
    concept: ConceptType
    name: str

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]: ...


def run_enumerator(enumerator: ConceptEnumerator, ctx: EnumContext) -> list[ConceptArtifact]:
    return list(enumerator.enumerate(ctx))
