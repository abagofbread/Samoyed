from __future__ import annotations

from samoyed.enrichment.catalog import MATERIAL_KINDS
from samoyed.enrichment.impact import IMPACT_KIND_REGISTRY
from samoyed.fixtures.enrichment_registry import (
    get_enrichment_example,
    read_enrichment_example_bytes,
)
from samoyed.fixtures.registry import get_fixture
from samoyed.sessions import SESSION_STORE


def test_new_material_and_impact_kinds_registered():
    for kind in ("api_key", "oauth_token", "email_credential", "k8s_service_account_token"):
        assert kind in MATERIAL_KINDS
    for kind in ("external_service", "email_account", "k8s_service_account", "s3_bucket"):
        assert kind in IMPACT_KIND_REGISTRY


def test_aws_goat_fixture_and_example_registered():
    assert get_fixture("aws-goat").filename == "aws_goat_env.json"
    example = get_enrichment_example("aws-goat-creds")
    assert example.lab_fixture == "aws-goat"


def _load_and_enrich(tmp_path, monkeypatch, session_id="goat-enrich"):
    monkeypatch.chdir(tmp_path)
    SESSION_STORE.load_fixture("aws-goat", session_id=session_id)
    stats = SESSION_STORE.apply_enrichment(
        session_id, read_enrichment_example_bytes("aws-goat-creds")
    )
    snapshot = SESSION_STORE.resolve_session_ref(session_id).snapshot
    return stats, snapshot


def test_goat_enrichment_attaches_all_credential_kinds(tmp_path, monkeypatch):
    stats, snapshot = _load_and_enrich(tmp_path, monkeypatch)

    assert stats["materials_applied"] == 4
    assert stats["skipped_materials"] == []

    material_kinds = {
        n.props.get("material_kind")
        for n in snapshot.nodes.values()
        if n.props.get("native_kind") == "PivotMaterial"
    }
    assert {"api_key", "oauth_token", "email_credential", "k8s_service_account_token"} <= material_kinds

    # Every material is anchored to the compromised web instance via HAS_MATERIAL.
    ec2 = next(
        nid
        for nid, n in snapshot.nodes.items()
        if n.props.get("resource_type") == "EC2Instance"
    )
    has_material = [
        e for e in snapshot.edges if e.src_id == ec2 and e.rel_type == "HAS_MATERIAL"
    ]
    assert len(has_material) == 4


def test_goat_credentials_pivot_to_external_services(tmp_path, monkeypatch):
    _stats, snapshot = _load_and_enrich(tmp_path, monkeypatch)

    external = {
        n.props.get("display_name"): n
        for n in snapshot.nodes.values()
        if n.props.get("resource_type") in {"ExternalService", "EmailAccount"}
    }
    # The three off-cloud pivots were projected and flagged external.
    assert {"stripe-payments-api", "github-org-acme-corp", "no-reply@acme-corp.com"} <= set(external)
    assert all(n.props.get("is_external") is True for n in external.values())

    # Each external node is reached by an UNLOCKS edge from a harvested credential.
    unlock_dsts = {e.dst_id for e in snapshot.edges if e.rel_type == "UNLOCKS"}
    for node in external.values():
        node_id = next(nid for nid, n in snapshot.nodes.items() if n is node)
        assert node_id in unlock_dsts


def test_goat_credentials_also_pivot_to_internal_nodes(tmp_path, monkeypatch):
    _stats, snapshot = _load_and_enrich(tmp_path, monkeypatch)

    def unlock_dst_display() -> set[str]:
        out = set()
        for e in snapshot.edges:
            if e.rel_type != "UNLOCKS":
                continue
            dst = snapshot.nodes.get(e.dst_id)
            if dst:
                out.add(str(dst.props.get("display_name") or ""))
        return out

    displays = unlock_dst_display()
    # API key also reaches the in-account S3 bucket.
    assert "goat-app-assets" in displays
    # Stolen SA token unlocks the SA and, via IRSA web identity, the IAM role.
    assert any("app-sa" in d for d in displays)
    irsa_unlocks = [
        e
        for e in snapshot.edges
        if e.rel_type == "UNLOCKS"
        and e.props.get("mechanism") == "AssumeRoleWithWebIdentity"
    ]
    assert irsa_unlocks
    role_id = irsa_unlocks[0].dst_id
    assert "goat-eks-irsa-role" in str(snapshot.nodes[role_id].props.get("display_name"))
