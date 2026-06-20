from __future__ import annotations

from typing import Callable, TypeVar

from samoyed.cloud.artifacts import DenialRecord
from samoyed.cloud.concepts import CloudProvider
from samoyed.credentials.protocol import EnumContext

T = TypeVar("T")


def is_gcp_denied(exc: Exception) -> bool:
    code = getattr(exc, "code", None)
    if code is not None:
        return int(code) in {401, 403, 7}  # 7 = PERMISSION_DENIED in gRPC
    return "403" in str(exc) or "Permission" in str(exc)


def call_gcp(ctx: EnumContext, *, operation: str, call: Callable[[], T]) -> T | None:
    try:
        return call()
    except Exception as exc:
        if is_gcp_denied(exc):
            ctx.denial_log.add(
                DenialRecord(
                    provider=CloudProvider.GCP,
                    operation=operation,
                    error_code=str(getattr(exc, "code", "PermissionDenied")),
                    message=str(exc),
                )
            )
            return None
        raise
