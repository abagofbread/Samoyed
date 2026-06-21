from __future__ import annotations

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.graph.sample_enterprise import build_sample_enterprise_graph
from samoyed.path_engine.search import find_attack_paths
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def _enterprise_start(snapshot):
    return next(
        node_id
        for node_id, node in snapshot.nodes.items()
        if node.props.get("is_scenario_start")
    )


def test_enterprise_graph_has_three_storyline_targets():
    snapshot = build_sample_enterprise_graph("enterprise-structure")
    native_ids = {n.props.get("native_id") for n in snapshot.nodes.values()}
    assert "S3Bucket:corp-secret-vault" in native_ids
    assert "S3Bucket:sales-leads-export" in native_ids
    assert any("prod/platform-master" in str(nid) for nid in native_ids)


def test_metadata_sts_chain_reaches_prod_secret():
    snapshot = build_sample_enterprise_graph("enterprise-sts")
    start = _enterprise_start(snapshot)
    secret = next(
        nid
        for nid, n in snapshot.nodes.items()
        if n.props.get("resource_type") == "Secret" and "platform-master" in str(n.props.get("name", ""))
    )

    paths = find_attack_paths(
        snapshot,
        start_node_id=start,
        target_concept="SecretStore",
        max_depth=12,
    )
    secret_paths = [p for p in paths if secret in p.node_ids]
    assert secret_paths
    best = max(secret_paths, key=lambda p: len(p.steps))
    rels = [s.rel_type for s in best.steps]
    assert rels[0] == "EXECUTES_AS"
    assert "CAN_ASSUME_ROLE" in rels
    assert rels[-1] == "READS"
    assert len(best.steps) >= 7


def test_engineering_path_reaches_vault_bucket():
    snapshot = build_sample_enterprise_graph("enterprise-eks")
    start = _enterprise_start(snapshot)
    vault = next(
        nid for nid, n in snapshot.nodes.items() if n.props.get("bucket_name") == "corp-secret-vault"
    )

    paths = find_attack_paths(snapshot, start_node_id=start, target_concept="DataStore", max_depth=12)
    vault_paths = [p for p in paths if vault in p.node_ids]
    assert vault_paths
    longest = max(vault_paths, key=lambda p: len(p.steps))
    rels = [s.rel_type for s in longest.steps]
    assert "PROJECTS_TO" in rels or "READS" in rels
    assert len(longest.steps) >= 8


def test_marketing_analyst_lambda_path_to_sales_secret():
    snapshot = build_sample_enterprise_graph("enterprise-marketing")
    analyst = next(
        nid
        for nid, n in snapshot.nodes.items()
        if n.props.get("display_name") == "marketing-analyst"
    )
    sales_secret = next(
        nid
        for nid, n in snapshot.nodes.items()
        if n.props.get("name") == "sales/hubspot-token"
    )

    paths = find_attack_paths(snapshot, start_node_id=analyst, target_concept="SecretStore", max_depth=8)
    assert any(sales_secret in p.node_ids for p in paths)


def test_create_sample_enterprise_session_api():
    res = client.post("/api/sessions/sample-enterprise")
    assert res.status_code == 200
    data = res.json()
    assert data["session_id"]
    assert "i-marketing-web" in data["caller_arn"]
    assert data["metadata"]["scenario"] == "enterprise-mock"

    resolved = SESSION_STORE.resolve_start_node(data["session_id"], "caller")
    assert resolved

    paths = client.post(
        f"/api/sessions/{data['session_id']}/paths/query",
        json={"start": "caller", "target_concept": "SecretStore", "max_depth": 12},
    )
    assert paths.status_code == 200
    assert len(paths.json()["paths"]) >= 5
