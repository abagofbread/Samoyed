from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from samoyed.cloud.concepts import CapabilityType, CloudProvider

ProbeStatus = Literal["allowed", "denied", "error"]


@dataclass(frozen=True)
class ApiProbe:
    """Single API call to attempt with leaked / low-privilege credentials."""

    operation: str
    description: str
    capability: CapabilityType
    resource_type: str | None = None
    concept_type: str | None = None  # SecretStore, DataStore, etc.
    high_value: bool = False


@dataclass
class ProbeResult:
    operation: str
    status: ProbeStatus
    error_code: str = ""
    message: str = ""
    resources: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProbeReport:
    provider: CloudProvider
    caller_native_id: str
    scope_id: str
    results: list[ProbeResult] = field(default_factory=list)

    @property
    def allowed(self) -> list[ProbeResult]:
        return [r for r in self.results if r.status == "allowed"]

    @property
    def denied(self) -> list[ProbeResult]:
        return [r for r in self.results if r.status == "denied"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "caller_native_id": self.caller_native_id,
            "scope_id": self.scope_id,
            "allowed_count": len(self.allowed),
            "denied_count": len(self.denied),
            "results": [
                {
                    "operation": r.operation,
                    "status": r.status,
                    "error_code": r.error_code,
                    "message": r.message,
                    "resource_count": len(r.resources),
                    "resources": r.resources[:20],
                }
                for r in self.results
            ],
        }


ProbeRunner = Callable[[Any, ApiProbe], ProbeResult]
