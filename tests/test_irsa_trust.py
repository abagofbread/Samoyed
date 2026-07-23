"""IRSA trust-validation: OIDC Conditions → SA PROJECTS_TO."""

from __future__ import annotations

from samoyed.attack.irsa_trust import enrich_irsa_trust
from samoyed.cloud.concepts import ConceptType
from samoyed.credentials.k8s import sa_native_id
from samoyed.graph.builder import GraphBuilder
from samoyed.policy.irsa import parse_irsa_trust_document, sa_refs_for_match


OIDC = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
ROLE = "arn:aws:iam::111111111111:role/eks-workload-admin"


def _irsa_trust(*, sub: str, string_like: bool = False) -> dict:
    op = "StringLike" if string_like else "StringEquals"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": OIDC},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    op: {
                        f"{OIDC.replace('arn:aws:iam::111111111111:oidc-provider/', '')}:sub": sub,
                        f"{OIDC.replace('arn:aws:iam::111111111111:oidc-provider/', '')}:aud": "sts.amazonaws.com",
                    }
                },
            }
        ],
    }


def test_parse_exact_sa_sub():
    trust = _irsa_trust(sub="system:serviceaccount:default:irsa-sa")
    # Use realistic condition keys (issuer path :sub)
    trust["Statement"][0]["Condition"] = {
        "StringEquals": {
            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:default:irsa-sa",
            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com",
        }
    }
    matches = parse_irsa_trust_document(trust, role_arn=ROLE)
    assert len(matches) == 1
    assert matches[0].namespace == "default"
    assert matches[0].sa_name == "irsa-sa"
    assert matches[0].audience == "sts.amazonaws.com"


def test_parse_namespace_wildcard_expands_inventored():
    trust = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": OIDC},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringLike": {
                        "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:payments:*",
                    }
                },
            }
        ]
    }
    matches = parse_irsa_trust_document(trust, role_arn=ROLE)
    assert len(matches) == 1
    assert matches[0].sa_name is None
    refs = sa_refs_for_match(
        matches[0],
        inventored_sas=[("payments", "api"), ("payments", "worker"), ("default", "other")],
    )
    assert refs == [("payments", "api"), ("payments", "worker")]


def test_enrich_irsa_trust_wires_validated_projects_to():
    builder = GraphBuilder("irsa-trust-exact")
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
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com",
                            }
                        },
                    }
                ]
            },
        },
    )
    stats = enrich_irsa_trust(builder)
    assert stats["irsa_projects_to"] >= 1
    sa_native = sa_native_id("default", "irsa-sa")
    sa = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_id") == sa_native)
    edges = [
        e
        for e in builder.snapshot.edges
        if e.src_id == sa.node_id and e.dst_id == role and e.rel_type == "PROJECTS_TO"
    ]
    assert len(edges) == 1
    assert edges[0].props.get("trust_validated") is True
    assert edges[0].props.get("binding_type") == "IRSA"
    assert edges[0].props.get("mechanism") == "oidc-sub"


def test_annotation_mismatch_left_unvalidated():
    builder = GraphBuilder("irsa-trust-mismatch")
    role_trusted = builder.add_concept_node(
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
    other_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/wrong-role",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/wrong-role", "name": "wrong-role"},
    )
    sa = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=sa_native_id("default", "irsa-sa"),
        props={"native_kind": "ServiceAccount", "namespace": "default", "name": "irsa-sa"},
    )
    builder.add_edge(
        src_id=sa,
        rel_type="PROJECTS_TO",
        dst_id=other_role,
        props={"binding_type": "IRSA", "annotation": "eks.amazonaws.com/role-arn"},
    )

    stats = enrich_irsa_trust(builder)
    assert stats["irsa_annotation_unvalidated"] >= 1

    ann = next(
        e
        for e in builder.snapshot.edges
        if e.src_id == sa and e.dst_id == other_role and e.rel_type == "PROJECTS_TO"
    )
    assert ann.props.get("trust_validated") is False

    validated = next(
        e
        for e in builder.snapshot.edges
        if e.src_id == sa and e.dst_id == role_trusted and e.rel_type == "PROJECTS_TO"
    )
    assert validated.props.get("trust_validated") is True


def test_stringlike_ns_wildcard_uses_inventored_sas():
    builder = GraphBuilder("irsa-trust-wild")
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
                            "StringLike": {
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": (
                                    "system:serviceaccount:payments:*"
                                ),
                            }
                        },
                    }
                ]
            },
        },
    )
    sa_a = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=sa_native_id("payments", "api"),
        props={"native_kind": "ServiceAccount", "namespace": "payments", "name": "api"},
    )
    sa_b = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=sa_native_id("payments", "worker"),
        props={"native_kind": "ServiceAccount", "namespace": "payments", "name": "worker"},
    )
    builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=sa_native_id("default", "other"),
        props={"native_kind": "ServiceAccount", "namespace": "default", "name": "other"},
    )

    stats = enrich_irsa_trust(builder)
    assert stats["irsa_projects_to"] >= 2
    linked = {
        e.src_id
        for e in builder.snapshot.edges
        if e.dst_id == role and e.rel_type == "PROJECTS_TO" and e.props.get("trust_validated")
    }
    assert sa_a in linked
    assert sa_b in linked
