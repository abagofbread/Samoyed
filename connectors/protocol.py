from __future__ import annotations

from pathlib import Path
from typing import Iterator, Protocol

from samoyed.cloud.artifacts import ConceptArtifact


class Connector(Protocol):
    name: str

    def detect(self, path: Path) -> bool: ...

    def ingest(self, path: Path) -> Iterator[ConceptArtifact]: ...
