from __future__ import annotations

import json
from typing import Any

from samoyed.fixtures.registry import (
    FixtureSpec,
    fixture_lab_path,
    get_fixture,
    list_fixtures,
    read_fixture_bytes,
)
from samoyed.sessions import SESSION_STORE, SessionRecord


def load_fixture_session(
    fixture_id: str,
    *,
    session_id: str | None = None,
    caller_arn: str | None = None,
) -> SessionRecord:
    """Import a bundled field-realistic report through the connector pipeline."""
    spec = get_fixture(fixture_id)
    lab = fixture_lab_path(fixture_id)
    if lab is not None:
        record = _load_lab_fixture(spec, lab, session_id=session_id, caller_arn=caller_arn)
    else:
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


def _load_lab_fixture(
    spec: FixtureSpec,
    lab: Any,
    *,
    session_id: str | None,
    caller_arn: str | None,
) -> SessionRecord:
    from samoyed.connectors.terraform.autoload import apply_companion_enrichments
    from samoyed.connectors.terraform.importer import load_terraform_from_path

    payload_obj = load_terraform_from_path(lab)
    record = SESSION_STORE.create_import_session(
        spec.connector,
        json.dumps(payload_obj),
        caller_arn=caller_arn,
        session_id=session_id,
    )
    enrich_runs = apply_companion_enrichments(SESSION_STORE, record.session_id, lab)
    record = SESSION_STORE.get(record.session_id) or record
    if enrich_runs:
        record.metadata["companion_enrichments"] = [
            {"path": r.get("path"), "materials_applied": r.get("materials_applied")}
            for r in enrich_runs
        ]
    record.metadata["lab_dir"] = str(lab)
    return record


def list_fixture_catalog(*, demo_only: bool = False) -> list[dict[str, Any]]:
    return list_fixtures(demo_only=demo_only)
