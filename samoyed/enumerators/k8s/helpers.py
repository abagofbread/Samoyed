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


def rule_grants(rules: list[dict[str, Any]]) -> list[tuple[str, str, str | None]]:
    """Map RBAC rules to (rel_type, target_concept, action) triples."""
    grants: list[tuple[str, str, str | None]] = []
    for rule in rules or []:
        verbs = set(rule.get("verbs") or [])
        resources = set(rule.get("resources") or [])
        if not verbs:
            continue
        wildcard_resources = "*" in resources
        if verbs & {"*", "create", "update", "patch", "delete", "deletecollection"}:
            if "secrets" in resources or wildcard_resources:
                grants.append(("WRITES", "SecretStore", None))
            pod_exec = "pods/exec" in resources or wildcard_resources
            pod_resource = "pods" in resources or wildcard_resources
            if pod_exec and (verbs & {"*", "create"}):
                grants.append(("CONTROLS", "Workload", "rbac:pods:exec"))
            if pod_resource and (verbs & {"*", "create", "update", "patch", "delete", "deletecollection"}):
                grants.append(("CONTROLS", "Workload", "rbac:pods:create"))
        if verbs & {"*", "get", "list", "watch"}:
            if "secrets" in resources or wildcard_resources:
                grants.append(("READS", "SecretStore", None))
            if "pods" in resources or wildcard_resources:
                grants.append(("READS", "Workload", None))
        if verbs & {"*"} and resources & {"*"}:
            grants.append(("CAN_ACCESS", "ManagementEndpoint", None))
    return grants


DANGEROUS_CLUSTER_ROLES = frozenset({"cluster-admin", "admin", "cluster-administrator"})

GRANT_TARGET_CONCEPT: dict[str, ConceptType] = {
    "SecretStore": ConceptType.SECRET_STORE,
    "ManagementEndpoint": ConceptType.MANAGEMENT_ENDPOINT,
    "Workload": ConceptType.WORKLOAD,
}
