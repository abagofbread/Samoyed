from __future__ import annotations

from typing import Callable, TypeVar

from samoyed.cloud.artifacts import DenialRecord
from samoyed.cloud.concepts import CloudProvider
from samoyed.credentials.protocol import EnumContext

T = TypeVar("T")


def is_azure_denied(exc: Exception) -> bool:
    if getattr(exc, "status_code", None) in {401, 403}:
        return True
    return "403" in str(exc) or "AuthorizationFailed" in str(exc)


def call_azure(ctx: EnumContext, *, operation: str, call: Callable[[], T]) -> T | None:
    try:
        return call()
    except Exception as exc:
        if is_azure_denied(exc):
            ctx.denial_log.add(
                DenialRecord(
                    provider=CloudProvider.AZURE,
                    operation=operation,
                    error_code=str(getattr(exc, "status_code", "AuthorizationFailed")),
                    message=str(exc),
                )
            )
            return None
        raise
