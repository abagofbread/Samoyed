from __future__ import annotations

from typing import Callable, TypeVar

from samoyed.cloud.artifacts import DenialRecord
from samoyed.cloud.concepts import CloudProvider
from samoyed.credentials.protocol import EnumContext

T = TypeVar("T")


def is_azure_denied(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    if status in {401, 403}:
        return True
    # azure.core.exceptions.HttpResponseError often exposes .status_code / .error
    response = getattr(exc, "response", None)
    if response is not None and getattr(response, "status_code", None) in {401, 403}:
        return True
    text = str(exc)
    return (
        "403" in text
        or "401" in text
        or "AuthorizationFailed" in text
        or "ClientAuthenticationError" in type(exc).__name__
    )


def call_azure(ctx: EnumContext, *, operation: str, call: Callable[[], T]) -> T | None:
    try:
        return call()
    except ImportError:
        return None
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
        # Soft-fail when a resource/operation is absent (NIC/PIP lookups, etc.)
        status = getattr(exc, "status_code", None) or getattr(
            getattr(exc, "response", None), "status_code", None
        )
        if status in {404, 405, 501}:
            return None
        raise
