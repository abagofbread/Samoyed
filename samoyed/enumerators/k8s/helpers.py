from __future__ import annotations

from typing import Any, Callable, TypeVar

from samoyed.cloud.artifacts import DenialRecord
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.protocol import EnumContext

T = TypeVar("T")


def is_forbidden(exc: Exception) -> bool:
    try:
        from kubernetes.client.rest import ApiException
    except ImportError:
        return False
    if isinstance(exc, ApiException):
        return exc.status in {401, 403}
    return False


def call_k8s(ctx: EnumContext, *, operation: str, call: Callable[[], T]) -> T | None:
    try:
        return call()
    except Exception as exc:
        if is_forbidden(exc):
            code = getattr(exc, "reason", None) or getattr(exc, "status", "Forbidden")
            ctx.denial_log.add(
                DenialRecord(
                    provider=CloudProvider.KUBERNETES,
                    operation=operation,
                    error_code=str(code),
                    message=str(exc),
                )
            )
            return None
        raise


def rule_grants(rules: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Map RBAC rules to (rel_type, target_concept) pairs."""
    grants: list[tuple[str, str]] = []
    for rule in rules or []:
        verbs = set(rule.get("verbs") or [])
        resources = set(rule.get("resources") or [])
        if not verbs:
            continue
        if verbs & {"*", "create", "update", "patch", "delete", "deletecollection"}:
            if "secrets" in resources or "*" in resources:
                grants.append(("WRITES", "SecretStore"))
            if "pods" in resources or "*" in resources:
                grants.append(("CONTROLS", "Workload"))
        if verbs & {"*", "get", "list", "watch"}:
            if "secrets" in resources or "*" in resources:
                grants.append(("READS", "SecretStore"))
            if "pods" in resources or "*" in resources:
                grants.append(("READS", "Workload"))
        if verbs & {"*"} and resources & {"*"}:
            grants.append(("CAN_ACCESS", "ManagementEndpoint"))
    return grants


DANGEROUS_CLUSTER_ROLES = frozenset({"cluster-admin", "admin", "cluster-administrator"})

GRANT_TARGET_CONCEPT: dict[str, ConceptType] = {
    "SecretStore": ConceptType.SECRET_STORE,
    "ManagementEndpoint": ConceptType.MANAGEMENT_ENDPOINT,
    "Workload": ConceptType.WORKLOAD,
}
