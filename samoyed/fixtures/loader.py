from __future__ import annotations

from typing import Any

from samoyed.fixtures.registry import FixtureSpec, get_fixture, list_fixtures, read_fixture_bytes
from samoyed.sessions import SESSION_STORE, SessionRecord


def load_fixture_session(
    fixture_id: str,
    *,
    session_id: str | None = None,
    caller_arn: str | None = None,
) -> SessionRecord:
    """Import a bundled field-realistic report through the connector pipeline."""
    spec = get_fixture(fixture_id)
    payload = read_fixture_bytes(fixture_id)
    record = SESSION_STORE.create_import_session(
        spec.connector,
        payload,
        caller_arn=caller_arn,
        session_id=session_id,
    )
    record.metadata.setdefault("fixture_id", fixture_id)
    record.metadata["demo"] = spec.demo
    record.metadata["description"] = spec.description
    SESSION_STORE._persist(record)
    SESSION_STORE._sessions[record.session_id] = record
    return record


def list_fixture_catalog(*, demo_only: bool = False) -> list[dict[str, Any]]:
    return list_fixtures(demo_only=demo_only)
