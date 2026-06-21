from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from samoyed.cloud.concepts import CloudProvider

_AWS_ACCOUNT_RE = re.compile(r"(?:^|:)(\d{12})(?:$|:)")
_AWS_ARN_ACCOUNT_RE = re.compile(r"arn:aws:[^:]*::(\d{12}):")


def _slug(value: str, *, max_len: int = 48) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    if not cleaned:
        return "unknown"
    return cleaned[:max_len]


def extract_scope_key(
    provider: CloudProvider,
    scope_id: str,
    *,
    caller_arn: str = "",
    metadata: dict[str, Any] | None = None,
) -> str:
    """Stable ARN-ish identifier for the org/account/project scope."""
    metadata = metadata or {}
    for candidate in (
        metadata.get("account_id"),
        metadata.get("cartography_account_id"),
        metadata.get("cartography_project_id"),
        metadata.get("project_id"),
        metadata.get("subscription_id"),
    ):
        if candidate:
            return _slug(str(candidate))

    for arn in (caller_arn, scope_id):
        if not arn:
            continue
        match = _AWS_ARN_ACCOUNT_RE.search(arn)
        if match:
            return match.group(1)

    if provider == CloudProvider.AWS:
        match = _AWS_ACCOUNT_RE.search(scope_id)
        if match:
            return match.group(1)

    if scope_id.startswith("aws:"):
        tail = scope_id.split(":", 1)[-1]
        if tail.isdigit() and len(tail) == 12:
            return tail

    if provider == CloudProvider.KUBERNETES and scope_id:
        return _slug(scope_id.split("/")[-1] or scope_id)

    return _slug(scope_id or caller_arn or "unknown")


def derive_short_name(provider: CloudProvider, scope_key: str) -> str:
    """Predictable short name bound to scope — e.g. aws-123456789012."""
    prefix = provider.value.replace("_", "-")
    return f"{prefix}-{_slug(scope_key, max_len=40)}"


def build_session_id(
    short_name: str,
    created_at: datetime,
    scope_key: str,
    existing_ids: set[str] | None = None,
) -> str:
    """Format: shortName_YYYYMMDD_scopeKey with optional -N suffix on collision."""
    existing_ids = existing_ids or set()
    date_part = created_at.strftime("%Y%m%d")
    base = f"{short_name}_{date_part}_{_slug(scope_key, max_len=48)}"
    if base not in existing_ids:
        return base
    suffix = 2
    while f"{base}-{suffix}" in existing_ids:
        suffix += 1
    return f"{base}-{suffix}"


def parse_session_id(session_id: str) -> dict[str, str] | None:
    """Parse ergonomic ids; returns None for legacy/demo ids."""
    if session_id.startswith("sample-"):
        return None
    parts = session_id.split("_", 2)
    if len(parts) < 3:
        return None
    short_name, date_part, scope_part = parts
    if not re.fullmatch(r"\d{8}", date_part):
        return None
    scope_key = re.sub(r"-\d+$", "", scope_part)
    return {"short_name": short_name, "date": date_part, "scope_key": scope_key}


def session_short_name(session_id: str, metadata: dict[str, Any] | None = None) -> str | None:
    metadata = metadata or {}
    if metadata.get("short_name"):
        return str(metadata["short_name"])
    parsed = parse_session_id(session_id)
    if parsed:
        return parsed["short_name"]
    return None


def rebind_graph_session_id(snapshot, old_session_id: str, new_session_id: str) -> None:
    """Rewrite CollectionSession node id after allocating the final session id."""
    from samoyed.graph.builder import stable_id

    if old_session_id == new_session_id:
        snapshot.session_id = new_session_id
        return

    old_node_id = stable_id("CollectionSession", old_session_id)
    new_node_id = stable_id("CollectionSession", new_session_id)
    node = snapshot.nodes.pop(old_node_id, None)
    if node:
        node.node_id = new_node_id
        node.props["session_id"] = new_session_id
        snapshot.nodes[new_node_id] = node
    for edge in snapshot.edges:
        if edge.src_id == old_node_id:
            edge.src_id = new_node_id
        if edge.dst_id == old_node_id:
            edge.dst_id = new_node_id
    snapshot.session_id = new_session_id
