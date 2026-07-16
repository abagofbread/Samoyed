from __future__ import annotations

from typing import Callable, Iterator

from botocore.exceptions import ClientError

from samoyed.cloud.artifacts import ConceptArtifact, DenialRecord
from samoyed.credentials.aws import is_access_denied
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.contracts import ConceptEnumerator


# Expected "resource not configured" / empty-state codes — not denials, not fatal.
SOFT_AWS_ERROR_CODES = frozenset(
    {
        "NoSuchWebsiteConfiguration",
        "NoSuchTagSet",
        "NoSuchBucketPolicy",
        "NoSuchPublicAccessBlockConfiguration",
        "ServerSideEncryptionConfigurationNotFoundError",
        "ReplicationConfigurationNotFoundError",
        "NoSuchLifecycleConfiguration",
        "NoSuchCORSConfiguration",
        "PermanentRedirect",  # wrong-region bucket head — skip rather than crash enum
        "404",
        "NotFound",
        "ResourceNotFoundException",
        "NoSuchEntity",
        "EntityDoesNotExistException",
        "AccessAnalyzerNotFoundException",
        "ResourceNotFound",
    }
)


def paginate_call(
    ctx: EnumContext,
    *,
    operation: str,
    call: Callable[[], dict],
    soft_errors: frozenset[str] | None = None,
) -> dict | None:
    soft = SOFT_AWS_ERROR_CODES if soft_errors is None else soft_errors
    try:
        return call()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if is_access_denied(exc):
            ctx.denial_log.add(
                DenialRecord(
                    provider=ctx.scope.provider,
                    operation=operation,
                    error_code=code or "AccessDenied",
                    message=str(exc),
                )
            )
            return None
        if code in soft or str(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")) in soft:
            return None
        raise


class EnumeratorRunner:
    def __init__(self, enumerators: list[ConceptEnumerator]) -> None:
        self.enumerators = enumerators

    def run_all(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        for enum in self.enumerators:
            yield from enum.enumerate(ctx)
