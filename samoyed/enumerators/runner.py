from __future__ import annotations

from typing import Callable, Iterator

from botocore.exceptions import ClientError

from samoyed.cloud.artifacts import ConceptArtifact, DenialRecord
from samoyed.credentials.aws import is_access_denied
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.contracts import ConceptEnumerator


def paginate_call(
    ctx: EnumContext,
    *,
    operation: str,
    call: Callable[[], dict],
) -> dict | None:
    try:
        return call()
    except ClientError as exc:
        if is_access_denied(exc):
            ctx.denial_log.add(
                DenialRecord(
                    provider=ctx.scope.provider,
                    operation=operation,
                    error_code=exc.response.get("Error", {}).get("Code", "AccessDenied"),
                    message=str(exc),
                )
            )
            return None
        raise


class EnumeratorRunner:
    def __init__(self, enumerators: list[ConceptEnumerator]) -> None:
        self.enumerators = enumerators

    def run_all(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        for enum in self.enumerators:
            yield from enum.enumerate(ctx)
