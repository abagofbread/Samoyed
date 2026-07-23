from __future__ import annotations

from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.attack.surface import enrich_attack_surface
from samoyed.change_impact import analyze_proposed_changes
from samoyed.graph.builder import GraphBuilder
from samoyed.path_engine.search import find_attack_paths
from samoyed.policy.access import (
    can_principal_access_node,
    find_isolation_breaches,
    principal_has_crypto_mining_risk,
)
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def _compute_lab(tmp_path, monkeypatch, session_id: str = "change-impact-lab"):
    monkeypatch.chdir(tmp_path)
    return SESSION_STORE.load_fixture("compute-exposure-lab", session_id=session_id)


def test_ssrf_metadata_chain_reaches_pci_bucket(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch)
    graph = record.snapshot

    ssrf_id = next(
        nid
        for nid, n in graph.nodes.items()
        if n.props.get("function_name") == "ssrf-fetcher"
    )
    pci_bucket_id = next(
        nid for nid, n in graph.nodes.items() if n.props.get("bucket_name") == "pci-internal-ledger"
    )

    paths = find_attack_paths(
        graph,
        start_node_id=ssrf_id,
        end_node_id=pci_bucket_id,
        max_depth=10,
        max_paths=3,
    )
    assert paths, "SSRF compute should reach PCI bucket via metadata → assume role → write"


def test_isolation_breach_detected_on_baseline(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch)
    breaches = find_isolation_breaches(record.snapshot)
    assert breaches, "Internet-exposed SSRF workload should breach PCI isolation"


def test_expose_bucket_change_is_significant(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch)
    result = analyze_proposed_changes(
        record.snapshot,
        [
            {
                "type": "expose_resource",
                "target": "public-uploads-staging",
                "properties": {"public_write": True, "exposure_level": "internet"},
            }
        ],
        context_principal="caller",
    )
    assert result.significant
    categories = {f.category for f in result.findings}
    assert "exposure_opened" in categories


def test_mining_risk_change_detected(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch)
    result = analyze_proposed_changes(
        record.snapshot,
        [
            {
                "type": "grant_action",
                "principal": "caller",
                "target": "arn:aws:iam::111111111111:role/crypto-launcher",
                "action": "ec2:RunInstances",
            },
            {
                "type": "grant_action",
                "principal": "caller",
                "target": "arn:aws:iam::111111111111:role/crypto-launcher",
                "action": "iam:PassRole",
            },
        ],
        context_principal="caller",
    )
    assert result.after["crypto_mining_at_risk"]
    assert any(f.category == "mining_risk" for f in result.findings)


def test_policy_access_check_api(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch, session_id="policy-access-api")
    res = client.post(
        f"/api/sessions/{record.session_id}/policy/access-check",
        json={
            "principal": "caller",
            "target": "pci-internal-ledger",
            "action": "s3:PutObject",
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert "access" in body
    assert "crypto_mining_risk" in body


def test_changes_analyze_api(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch, session_id="changes-analyze-api")
    res = client.post(
        f"/api/sessions/{record.session_id}/changes/analyze",
        json={
            "changes": [
                {
                    "type": "expose_resource",
                    "target": "S3Bucket:public-uploads-staging",
                    "properties": {"public_write": True},
                }
            ],
            "context_principal": "caller",
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["significant"] is True
    assert body["findings"]


def test_can_principal_access_via_attack_path(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch, session_id="access-via-path")
    access = can_principal_access_node(
        record.snapshot,
        "caller",
        "pci-internal-ledger",
        action="s3:PutObject",
    )
    assert access["allowed"]
    assert access["via"] in {"attack_path", "iam_action", "direct"}


def test_marketing_web_imds_reaches_pci_bucket(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch, session_id="marketing-web-imds")
    graph = record.snapshot
    marketing_id = next(
        nid for nid, n in graph.nodes.items() if n.props.get("name") == "marketing-web"
    )
    pci_bucket_id = next(
        nid for nid, n in graph.nodes.items() if n.props.get("bucket_name") == "pci-internal-ledger"
    )
    paths = find_attack_paths(
        graph,
        start_node_id=marketing_id,
        end_node_id=pci_bucket_id,
        max_depth=12,
        max_paths=3,
    )
    assert paths, "marketing-web EC2 should reach PCI bucket via IMDS → assume role → write"
    rels = [s.rel_type for s in paths[0].steps]
    assert "CAN_ESCAPE_TO" in rels or "EXECUTES_AS" in rels


def test_ml_gpu_compute_node_present(tmp_path, monkeypatch):
    record = _compute_lab(tmp_path, monkeypatch, session_id="gpu-node")
    gpu = next(
        (nid, n)
        for nid, n in record.snapshot.nodes.items()
        if n.props.get("name") == "ml-training-gpu"
    )
    assert gpu[1].props.get("gpu_accelerated")
    assert gpu[1].props.get("compute_class") == "gpu"
    assert gpu[1].props.get("instance_type") == "g4dn.xlarge"


def test_surface_enrichment_adds_imds_edges():
    builder = GraphBuilder("surface-test")
    ec2_id = builder.add_concept_node(
        concept_type=__import__("samoyed.cloud.concepts", fromlist=["ConceptType"]).ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:i-test",
        props={"resource_type": "EC2Instance", "display_name": "test-ec2", "instance_id": "i-test"},
    )
    role_id = builder.add_concept_node(
        concept_type=__import__("samoyed.cloud.concepts", fromlist=["ConceptType"]).ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/test-instance",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/test-instance"},
    )
    builder.add_edge(src_id=ec2_id, rel_type="EXECUTES_AS", dst_id=role_id, props={})
    stats = enrich_attack_surface(builder)
    assert stats["imds_surfaces"] >= 1


def test_imds_escape_is_per_instance_not_shared():
    from samoyed.attack.surface import enrich_attack_surface
    from samoyed.cloud.concepts import ConceptType
    from samoyed.graph.builder import GraphBuilder

    builder = GraphBuilder("imds-per-instance")
    marketing = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:arn:aws:ec2:us-east-1:1:instance/i-marketing",
        props={
            "resource_type": "EC2Instance",
            "name": "marketing-web",
            "instance_id": "i-marketing",
            "ssrf_vulnerable": True,
        },
    )
    gpu = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:arn:aws:ec2:us-east-1:1:instance/i-gpu",
        props={"resource_type": "EC2Instance", "name": "ml-training-gpu", "instance_id": "i-gpu"},
    )
    marketing_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/marketing-web-instance",
        props={"name": "marketing-web-instance", "arn": "arn:aws:iam::1:role/marketing-web-instance"},
    )
    gpu_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ml-gpu-runner",
        props={"name": "ml-gpu-runner", "arn": "arn:aws:iam::1:role/ml-gpu-runner"},
    )
    builder.add_edge(src_id=marketing, rel_type="EXECUTES_AS", dst_id=marketing_role, props={})
    builder.add_edge(src_id=gpu, rel_type="EXECUTES_AS", dst_id=gpu_role, props={})

    enrich_attack_surface(builder)
    graph = builder.snapshot

    # IMDS credential theft is a direct compute->role escape edge, per-instance:
    # marketing yields only its own role (never the GPU instance's role).
    marketing_targets = {
        dst
        for dst, rel, _ in graph.adjacency.get(marketing, [])
        if rel == "CAN_ESCAPE_TO"
    }
    assert marketing_targets == {marketing_role}
    assert gpu_role not in marketing_targets

    gpu_targets = {
        dst for dst, rel, _ in graph.adjacency.get(gpu, []) if rel == "CAN_ESCAPE_TO"
    }
    assert gpu_targets == {gpu_role}
