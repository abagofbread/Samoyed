from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from samoyed.cloud.artifacts import DenialLog
from samoyed.cloud.concepts import CloudProvider


@dataclass
class ScopeBoundary:
    provider: CloudProvider
    scope_id: str
    display_name: str
    properties: dict[str, Any] = field(default_factory=dict)


class CloudCredential(Protocol):
    provider: CloudProvider

    def resolve_scope(self) -> ScopeBoundary: ...

    def client(self, service: str, region: str | None = None) -> Any: ...


@dataclass
class EnumContext:
    credentials: CloudCredential
    session_id: str
    scope: ScopeBoundary
    denial_log: DenialLog = field(default_factory=DenialLog)
    region: str = "us-east-1"
