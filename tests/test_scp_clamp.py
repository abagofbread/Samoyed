"""SCP parse + effective-action clamping."""

from __future__ import annotations

from samoyed.attack.analyzer import (
    collect_principal_actions,
    collect_principal_scp_denies,
    has_required_actions,
)
from samoyed.attack.service_admin import classify_service_admins
from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.policy.scp import (
    ScpConstraints,
    merge_scp_documents,
    parse_scp_document,
    scp_props_for_scope,
)


FULL_AWS = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

DENY_IAM = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
    ],
}

ALLOW_EC2_ONLY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["ec2:*", "sts:AssumeRole"], "Resource": "*"}],
}


def test_parse_scp_allow_and_deny():
    doc = parse_scp_document(DENY_IAM, policy_id="p-deny-iam", name="DenyIAM")
    assert "*" in doc.allow_actions
    assert "iam:*" in doc.deny_actions


def test_merge_scps_intersects_allows():
    full = parse_scp_document(FULL_AWS, policy_id="p-full", name="FullAWSAccess")
    ec2 = parse_scp_document(ALLOW_EC2_ONLY, policy_id="p-ec2", name="EC2Only")
    merged = merge_scp_documents([full, ec2])
    assert len(merged.allow_sets) == 2
    assert not merged.deny_actions


def test_scp_deny_iam_clamps_iam_star():
    builder = GraphBuilder("scp-deny")
    builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id="aws:account:1",
        props={
            "account_id": "1",
            **scp_props_for_scope(
                merge_scp_documents(
                    [parse_scp_document(DENY_IAM, policy_id="p1", name="DenyIAM")]
                )
            ),
        },
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/adminish",
        props={"native_kind": "Role", "account_id": "1", "arn": "arn:aws:iam::1:role/adminish"},
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=builder.add_concept_node(
            concept_type=ConceptType.IDENTITY,
            native_id="IAM:*",
            props={"native_kind": "IAM"},
        ),
        props={"action": "iam:*", "resource": "*"},
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=builder.add_concept_node(
            concept_type=ConceptType.DATA_STORE,
            native_id="S3Bucket:*",
            props={"resource_type": "S3Bucket"},
        ),
        props={"action": "s3:*", "resource": "*"},
    )

    actions = collect_principal_actions(builder.snapshot, role)
    denies = collect_principal_scp_denies(builder.snapshot, role)
    assert "iam:*" not in actions
    assert "s3:*" in actions
    assert "iam:*" in denies
    assert not has_required_actions(actions, frozenset({"iam:CreateUser"}), denies=denies)
    assert has_required_actions(actions, frozenset({"s3:PutObject"}), denies=denies)


def test_scp_allow_ceiling_drops_s3_admin():
    builder = GraphBuilder("scp-ceiling")
    builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id="aws:account:1",
        props={
            "account_id": "1",
            **scp_props_for_scope(
                merge_scp_documents(
                    [
                        parse_scp_document(FULL_AWS, policy_id="p-full", name="Full"),
                        parse_scp_document(ALLOW_EC2_ONLY, policy_id="p-ec2", name="EC2"),
                    ]
                )
            ),
        },
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/wide",
        props={"native_kind": "Role", "account_id": "1", "arn": "arn:aws:iam::1:role/wide"},
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=builder.add_concept_node(
            concept_type=ConceptType.DATA_STORE,
            native_id="S3Bucket:*",
            props={"resource_type": "S3Bucket"},
        ),
        props={"action": "s3:*", "resource": "*"},
    )
    builder.add_edge(
        src_id=role,
        rel_type="EXECUTES",
        dst_id=builder.add_concept_node(
            concept_type=ConceptType.DATA_STORE,
            native_id="EC2Instance:*",
            props={"resource_type": "EC2Instance"},
        ),
        props={"action": "ec2:*", "resource": "*"},
    )

    actions = collect_principal_actions(builder.snapshot, role)
    assert "s3:*" not in actions
    assert "ec2:*" in actions
    hits = classify_service_admins(builder.snapshot, role, builder.snapshot.nodes[role].props)
    kinds = {h["kind"] for h in hits}
    assert "full-s3-admin" not in kinds
    assert "full-ec2-admin" in kinds


def test_scp_exempt_management_account_no_clamp():
    builder = GraphBuilder("scp-exempt")
    builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id="aws:account:1",
        props={
            "account_id": "1",
            **scp_props_for_scope(ScpConstraints(exempt=True)),
        },
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/mgmt",
        props={"native_kind": "Role", "account_id": "1"},
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=builder.add_concept_node(
            concept_type=ConceptType.IDENTITY,
            native_id="IAM:*",
            props={},
        ),
        props={"action": "iam:*", "resource": "*"},
    )
    actions = collect_principal_actions(builder.snapshot, role)
    assert "iam:*" in actions
