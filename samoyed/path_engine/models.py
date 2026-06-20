from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PathStep:
    step_index: int
    src_id: str
    rel_type: str
    dst_id: str
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str = "explicit"


@dataclass
class PathResult:
    path_id: str
    node_ids: list[str]
    score: float
    steps: list[PathStep]
    target_match: dict[str, Any] = field(default_factory=dict)
