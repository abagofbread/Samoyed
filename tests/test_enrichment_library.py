from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.enrichment.library import (
    list_enrichment_library,
    resolve_collect_output_path,
    stem_from_collect_target,
)
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def test_stem_from_collect_target():
    assert stem_from_collect_target("host") == "host-local"
    assert stem_from_collect_target("/tmp/foo/module-2") == "module-2"


def test_resolve_collect_output_path_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_ENRICHMENT_DIR", str(tmp_path))
    path = resolve_collect_output_path("host")
    assert path == tmp_path / "host-local.json"
    named = resolve_collect_output_path("host", name="bastion-01")
    assert named == tmp_path / "bastion-01.json"
    custom = resolve_collect_output_path("host", output=tmp_path / "elsewhere" / "x.json")
    assert custom == tmp_path / "elsewhere" / "x.json"


def test_list_and_apply_enrichment_library(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_ENRICHMENT_DIR", str(tmp_path))
    report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "collected_at": "2026-01-01T00:00:00+00:00",
        "material_count": 1,
        "bindings": [
            {
                "target_ref": "unbound",
                "bind_required": True,
                "materials": [
                    {
                        "kind": "none_observed",
                        "locator": "lab",
                        "confidence": "explicit",
                        "evidence": {},
                    }
                ],
            }
        ],
    }
    (tmp_path / "module-2.json").write_text(json.dumps(report), encoding="utf-8")

    listed = list_enrichment_library()
    assert listed[0]["filename"] == "module-2.json"
    assert listed[0]["valid"] is True

    api_list = client.get("/api/enrichment/library")
    assert api_list.status_code == 200
    body = api_list.json()
    assert body["directory"] == str(tmp_path)
    assert body["files"][0]["filename"] == "module-2.json"

    record = SESSION_STORE.load_fixture("host-pivot", session_id="enrich-lib-apply")
    # Pick a real node id from the fixture
    node_id = next(iter(record.snapshot.nodes))
    res = client.post(
        f"/api/sessions/{record.session_id}/enrichment/library/module-2.json",
        params={"target_node_id": node_id},
    )
    assert res.status_code == 200
    assert res.json()["stats"]["bindings_applied"] == 1

    # Unbound report without a forced bind still imports (fuzzy / hostless).
    ok = client.post(f"/api/sessions/{record.session_id}/enrichment/library/module-2.json")
    assert ok.status_code == 200
    assert ok.json()["stats"]["materials_applied"] >= 1
