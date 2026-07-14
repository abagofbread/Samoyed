from __future__ import annotations

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.change_impact import compare_attack_surfaces
from samoyed.fixtures.registry import read_fixture_bytes
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def _baseline_and_proposed_exposed(tmp_path, monkeypatch):
    """Canon lab vs same lab with public-write staging bucket."""
    monkeypatch.chdir(tmp_path)
    baseline = SESSION_STORE.load_fixture("compute-exposure-lab", session_id="canon-lab")

    proposed_record = SESSION_STORE.create_import_session(
        "iam-report",
        read_fixture_bytes("compute-exposure-lab"),
        session_id="proposed-lab",
        graph_role="proposed",
    )
    staging_id = next(
        nid
        for nid, n in proposed_record.snapshot.nodes.items()
        if n.props.get("bucket_name") == "public-uploads-staging"
    )
    proposed_record.snapshot.nodes[staging_id].props["public_write"] = True
    proposed_record.snapshot.nodes[staging_id].props["exposure_level"] = "internet"

    from samoyed.attack.surface import enrich_attack_surface
    from samoyed.graph.builder import GraphBuilder

    builder = GraphBuilder(proposed_record.session_id)
    builder.snapshot = proposed_record.snapshot
    enrich_attack_surface(builder)
    proposed_record.snapshot = builder.snapshot

    return baseline, proposed_record


def test_compare_detects_new_exposure(tmp_path, monkeypatch):
    baseline, proposed = _baseline_and_proposed_exposed(tmp_path, monkeypatch)
    result = compare_attack_surfaces(
        baseline.snapshot,
        proposed.snapshot,
        context_principal="caller",
    )
    assert result.significant
    categories = {f.category for f in result.findings}
    assert "exposure_opened" in categories or "new_attack_path" in categories


def test_compare_api_two_sessions(tmp_path, monkeypatch):
    baseline, proposed = _baseline_and_proposed_exposed(tmp_path, monkeypatch)
    SESSION_STORE.set_session_graph_role(baseline.session_id, graph_role="canon")
    res = client.post(
        "/api/sessions/compare",
        json={
            "baseline_ref": baseline.session_id,
            "proposed_ref": proposed.session_id,
            "context_principal": "caller",
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["significant"] is True
    assert body["baseline_summary"]["attack_path_signatures"] >= 0
    assert body["proposed_summary"]["internet_write_exposures"] >= 1


def test_proposed_session_graph_is_compare_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    proposed = SESSION_STORE.create_import_session(
        "iam-report",
        read_fixture_bytes("compute-exposure-lab"),
        session_id="proposed-only",
        graph_role="proposed",
    )
    res = client.get(f"/api/sessions/{proposed.session_id}/graph")
    assert res.status_code == 200
    body = res.json()
    assert body["access"] == "compare_only"
    assert "nodes" not in body
    assert body["node_count"] > 0


def test_canon_session_graph_is_full(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    canon = SESSION_STORE.load_fixture("compute-exposure-lab", session_id="canon-full")
    SESSION_STORE.set_session_graph_role(canon.session_id, graph_role="canon", graph_access="full")
    res = client.get(f"/api/sessions/{canon.session_id}/graph")
    assert res.status_code == 200
    body = res.json()
    assert body["access"] == "full"
    assert len(body["nodes"]) > 0


def test_identical_graphs_no_new_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    baseline = SESSION_STORE.load_fixture("compute-exposure-lab", session_id="same-a")
    proposed = SESSION_STORE.load_fixture("compute-exposure-lab", session_id="same-b")
    result = compare_attack_surfaces(baseline.snapshot, proposed.snapshot)
    assert not any(f.severity in {"critical", "high"} for f in result.findings)
