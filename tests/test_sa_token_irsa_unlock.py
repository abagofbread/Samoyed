"""Stolen K8s SA token → SA + IRSA IAM role unlocks (graph-inferred)."""

from __future__ import annotations

import base64
import json

from samoyed.attack.irsa_trust import enrich_irsa_trust
from samoyed.cloud.concepts import ConceptType
from samoyed.collectors.sa_token import decode_jwt_payload, enrich_sa_token_material, sa_ref_from_jwt_payload
from samoyed.credentials.k8s import sa_native_id
from samoyed.enrichment.apply import apply_enrichment_report
from samoyed.enrichment.impact import repair_credential_impact, wire_credential_impact
from samoyed.graph.builder import GraphBuilder
from samoyed.path_engine.explain import explain_path
from samoyed.path_engine.models import PathResult, PathStep


OIDC = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
ROLE = "arn:aws:iam::111111111111:role/eks-workload-admin"


def _jwt_for_sa(ns: str, name: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "sub": f"system:serviceaccount:{ns}:{name}",
                "iss": "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
                "aud": ["sts.amazonaws.com"],
            }
        ).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_decode_jwt_sa_sub():
    token = _jwt_for_sa("default", "irsa-sa")
    payload = decode_jwt_payload(token)
    assert payload is not None
    assert sa_ref_from_jwt_payload(payload) == ("default", "irsa-sa")


def test_enrich_sa_token_material_from_jwt_in_evidence():
    token = _jwt_for_sa("payments", "api")
    mat = enrich_sa_token_material(
        {
            "kind": "k8s_service_account_token",
            "locator": "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "evidence": {"match": token, "file": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
        }
    )
    assert mat["impact_targets"] == [{"kind": "k8s_service_account", "name": "payments:api"}]
    assert mat["evidence"]["jwt_sub"] == "system:serviceaccount:payments:api"


def test_sa_token_unlocks_sa_and_irsa_role():
    builder = GraphBuilder("sa-token-irsa")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:bastion",
        props={"resource_type": "EC2Instance", "name": "bastion", "display_name": "bastion"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=ROLE,
        props={
            "native_kind": "Role",
            "arn": ROLE,
            "name": "eks-workload-admin",
            "assume_role_policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Federated": OIDC},
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": (
                                    "system:serviceaccount:default:irsa-sa"
                                ),
                            }
                        },
                    }
                ]
            },
        },
    )
    enrich_irsa_trust(builder)

    token = _jwt_for_sa("default", "irsa-sa")
    report = {
        "enrichment_version": 1,
        "collector": "on-host",
        "collector_mode": "on-host",
        "host_hint": "bastion",
        "bindings": [
            {
                "target_ref": "bastion",
                "materials": [
                    {
                        "kind": "k8s_service_account_token",
                        "locator": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                        "confidence": "explicit",
                        "evidence": {"match": token, "file": "/tmp/token"},
                        "impact_targets": [{"kind": "k8s_service_account", "name": "default:irsa-sa"}],
                    }
                ],
            }
        ],
    }
    stats = apply_enrichment_report(builder, report)
    assert stats["unlocks_applied"] >= 2
    assert stats["hostless_bindings"] == 0

    sa_native = sa_native_id("default", "irsa-sa")
    sa = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == sa_native)
    mats = [n for n in builder.snapshot.nodes.values() if n.props.get("material_kind") == "k8s_service_account_token"]
    assert mats
    mat_id = mats[0].node_id

    unlocks = [e for e in builder.snapshot.edges if e.src_id == mat_id and e.rel_type == "UNLOCKS"]
    unlocked = {e.dst_id for e in unlocks}
    assert sa.node_id in unlocked
    assert role in unlocked
    web = next(e for e in unlocks if e.dst_id == role)
    assert web.props.get("mechanism") == "AssumeRoleWithWebIdentity"
    assert web.props.get("trust_validated") is True
    assert any(e.src_id == host and e.rel_type == "HAS_MATERIAL" for e in builder.snapshot.edges)


def test_sa_token_without_irsa_unlocks_sa_only():
    builder = GraphBuilder("sa-token-no-irsa")
    builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:node",
        props={"resource_type": "EC2Instance", "name": "node", "display_name": "node"},
    )
    sa = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=sa_native_id("default", "plain-sa"),
        props={"native_kind": "ServiceAccount", "namespace": "default", "name": "plain-sa"},
    )
    mat = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="material:k8s_service_account_token:deadbeef",
        props={
            "native_kind": "PivotMaterial",
            "material_kind": "k8s_service_account_token",
            "locator": "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "impact_targets": [{"kind": "k8s_service_account", "name": "default:plain-sa"}],
            "source": "collector-enrichment",
        },
    )
    result = wire_credential_impact(
        builder,
        builder.snapshot,
        material_node_id=mat,
        material_kind="k8s_service_account_token",
        locator="/token",
        impact_targets=[{"kind": "k8s_service_account", "name": "default:plain-sa"}],
    )
    assert result["unlocks_applied"] >= 1
    unlock_dsts = {e.dst_id for e in builder.snapshot.edges if e.src_id == mat and e.rel_type == "UNLOCKS"}
    assert sa in unlock_dsts
    assert result.get("irsa_web_identity_unlocks", 0) == 0


def test_explain_web_identity_and_projects_to():
    builder = GraphBuilder("explain-irsa")
    a = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="material:tok",
        props={"summary": "Kubernetes SA token", "native_kind": "PivotMaterial"},
    )
    b = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=ROLE,
        props={"display_name": "eks-workload-admin"},
    )
    c = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=sa_native_id("default", "irsa-sa"),
        props={"display_name": "default/irsa-sa"},
    )
    path = PathResult(
        path_id="x",
        node_ids=[a, b, c],
        score=1.0,
        steps=[
            PathStep(
                step_index=0,
                src_id=a,
                rel_type="UNLOCKS",
                dst_id=b,
                evidence={"mechanism": "AssumeRoleWithWebIdentity", "via_sa": "kubernetes:serviceaccount:default:irsa-sa"},
                confidence="inferred",
            ),
            PathStep(
                step_index=1,
                src_id=c,
                rel_type="PROJECTS_TO",
                dst_id=b,
                evidence={"binding_type": "IRSA", "trust_validated": True},
                confidence="explicit",
            ),
        ],
        target_match={},
    )
    explained = explain_path(builder.snapshot, path)
    assert "AssumeRoleWithWebIdentity" in explained["steps"][0]["narrative"]
    assert "OIDC trust validated" in explained["steps"][1]["narrative"]


def test_repair_wires_irsa_from_jwt_sub_on_material():
    builder = GraphBuilder("repair-sa-token")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=ROLE,
        props={
            "native_kind": "Role",
            "arn": ROLE,
            "assume_role_policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Federated": OIDC},
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": (
                                    "system:serviceaccount:default:irsa-sa"
                                ),
                            }
                        },
                    }
                ]
            },
        },
    )
    enrich_irsa_trust(builder)
    mat = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="material:k8s_service_account_token:abc",
        props={
            "native_kind": "PivotMaterial",
            "material_kind": "k8s_service_account_token",
            "locator": "/token",
            "evidence": {"jwt_sub": "system:serviceaccount:default:irsa-sa"},
            "source": "collector-enrichment",
        },
    )
    stats = repair_credential_impact(builder)
    assert stats["unlocks_applied"] >= 2
    unlock_dsts = {e.dst_id for e in builder.snapshot.edges if e.src_id == mat and e.rel_type == "UNLOCKS"}
    assert role in unlock_dsts
