from __future__ import annotations

from samoyed.cloud.concepts import CloudProvider


def make_scope_id(provider: CloudProvider, kind: str, identifier: str) -> str:
    """Build a stable scope identifier: e.g. aws:account:123456789012."""
    return f"{provider.value}:{kind}:{identifier}"


def normalize_scope_id(scope_id: str) -> str:
    """Canonicalize known legacy scope_id shapes.

    Historically some Azure fixtures used ``azure:scope:subscription:{id}``;
    live enum emits ``azure:subscription:{id}``.
    """
    if scope_id.startswith("azure:scope:"):
        return "azure:" + scope_id[len("azure:scope:") :]
    return scope_id


def parse_scope_id(scope_id: str) -> tuple[CloudProvider | None, str, str]:
    scope_id = normalize_scope_id(scope_id)
    parts = scope_id.split(":", 2)
    if len(parts) != 3:
        return None, "", scope_id
    try:
        provider = CloudProvider(parts[0])
    except ValueError:
        return None, parts[0], parts[2]
    return provider, parts[1], parts[2]
