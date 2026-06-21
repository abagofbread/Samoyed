from __future__ import annotations

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.graph.markings import apply_marking
from samoyed.graph.model import GraphEdge, GraphNode, GraphSnapshot
from samoyed.graph.relationships import normalize_relationship, propagate_compromise
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def _load_cicd_fixture(tmp_path, monkeypatch, session_id: str = "cicd-chain"):
    """Import cicd-supply-chain iam-report; analyst adds DEPENDS_ON edges in tests."""
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("cicd-supply-chain", session_id=session_id)
    snap = record.snapshot

    def by_display(name: str) -> str:
        return next(nid for nid, n in snap.nodes.items() if n.props.get("display_name") == name)

    return record, by_display("leaked-dev"), by_display("artifact-bucket"), by_display("build-pipeline"), by_display("prod-workloads")


def test_leaked_key_cicd_chain_propagates_to_prod(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record, _leaked, bucket_id, pipeline_id, prod_id = _load_cicd_fixture(tmp_path, monkeypatch)

    SESSION_STORE.declare_relationship(
        record.session_id,
        dependent="build-pipeline",
        dependency="artifact-bucket",
        propagate=False,
    )
    SESSION_STORE.declare_relationship(
        record.session_id,
        dependent="prod-workloads",
        dependency="build-pipeline",
        propagate=False,
    )

    SESSION_STORE.mark_nodes(record.session_id, ["leaked-dev"], compromised=True, source="test")
    snap = SESSION_STORE.get(record.session_id).snapshot

    assert snap.nodes[bucket_id].props.get("is_compromised")
    assert snap.nodes[bucket_id].props.get("propagated_via") == "WRITES"
    assert snap.nodes[pipeline_id].props.get("is_compromised")
    assert snap.nodes[pipeline_id].props.get("propagated_via") == "DEPENDS_ON"
    assert snap.nodes[prod_id].props.get("is_compromised")
    assert snap.nodes[prod_id].props.get("propagated_via") == "DEPENDS_ON"

    bucket = snap.nodes[bucket_id]
    assert bucket.props.get("is_control_point") is True


def test_depends_on_marks_control_point(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record, _, bucket_id, pipeline_id, _ = _load_cicd_fixture(tmp_path, monkeypatch, "cicd-2")

    SESSION_STORE.declare_relationship(
        record.session_id,
        dependent="build-pipeline",
        dependency="artifact-bucket",
        propagate=False,
    )
    bucket = SESSION_STORE.get(record.session_id).snapshot.nodes[bucket_id]
    assert bucket.props.get("is_control_point") is True
    assert pipeline_id in bucket.props.get("control_point_for", [])


def test_api_declare_dependency(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record, _, bucket_id, pipeline_id, prod_id = _load_cicd_fixture(tmp_path, monkeypatch, "cicd-3")

    res = client.post(
        f"/api/sessions/{record.session_id}/relationships",
        json={
            "dependent": "build-pipeline",
            "dependency": "artifact-bucket",
            "propagate": False,
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["rel_type"] == "DEPENDS_ON"
    assert body["dependency_id"] == bucket_id
    assert body["dependent_id"] == pipeline_id

    client.post(
        f"/api/sessions/{record.session_id}/relationships",
        json={"dependent": "prod-workloads", "dependency": "build-pipeline", "propagate": False},
    )
    client.post(
        f"/api/sessions/{record.session_id}/markings",
        json={"refs": ["leaked-dev"], "compromised": True},
    )
    listing = client.get(f"/api/sessions/{record.session_id}/markings")
    compromised_ids = {n["node_id"] for n in listing.json()["compromised"]}
    assert {bucket_id, pipeline_id, prod_id}.issubset(compromised_ids)


def test_normalize_depends_on_aliases():
    assert normalize_relationship("controlled_by")["rel_type"] == "DEPENDS_ON"
    assert normalize_relationship("depends on")["compromise_flow"] == "downstream"


def test_propagate_compromise_multi_hop():
    graph = GraphSnapshot(session_id="x")
    graph.add_node(GraphNode("prod", "ComputeContext", {"concept_type": "Workload"}))
    graph.add_node(GraphNode("cicd", "ComputeContext", {"concept_type": "Workload"}))
    graph.add_node(GraphNode("bucket", "Resource", {"concept_type": "DataStore"}))
    graph.add_edge(GraphEdge("prod", "DEPENDS_ON", "cicd", {"analyst_declared": True}))
    graph.add_edge(GraphEdge("cicd", "DEPENDS_ON", "bucket", {"analyst_declared": True}))
    apply_marking(graph.nodes["bucket"].props, compromised=True)

    propagated = propagate_compromise(graph)
    assert len(propagated) == 2
    assert graph.nodes["cicd"].props.get("is_compromised")
    assert graph.nodes["prod"].props.get("is_compromised")
