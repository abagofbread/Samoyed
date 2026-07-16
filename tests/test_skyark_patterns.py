"""SkyArk / Rhino-inspired shadow-admin pattern coverage."""

from __future__ import annotations

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.attack.high_value import enrich_high_value_targets
from samoyed.attack.patterns import AWS_ATTACK_PATTERNS
from samoyed.attack.shadow_admin import enrich_shadow_admins
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import is_shadow_admin


def _pattern_ids() -> set[str]:
    return {p.id for p in AWS_ATTACK_PATTERNS}


def test_skyark_patterns_present():
    ids = _pattern_ids()
    for needed in (
        "aws-iam-attach-group-policy",
        "aws-iam-put-group-policy",
        "aws-iam-passrole-instance-profile",
        "aws-glue-passrole-dev-endpoint",
        "aws-datapipeline-passrole",
        "aws-sagemaker-passrole-notebook",
        "aws-codestar-passrole",
        "aws-lambda-update-configuration-layer",
        "aws-ec2-passrole-ssm",
        "aws-iam-update-assume-role-and-sts",
    ):
        assert needed in ids


def test_attach_group_policy_marks_skyark_shadow():
    builder = GraphBuilder("skyark-group")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/group-mgr",
        props={
            "native_kind": "User",
            "arn": "arn:aws:iam::1:user/group-mgr",
            "name": "group-mgr",
            "provider": "aws",
            "is_caller": True,
        },
    )
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=user,
        props={"action": "iam:AttachGroupPolicy"},
    )
    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    assert any(e.pattern.id == "aws-iam-attach-group-policy" for e in edges)
    enrich_high_value_targets(builder, provider=CloudProvider.AWS)
    enrich_shadow_admins(builder, provider=CloudProvider.AWS)
    assert is_shadow_admin(builder.snapshot.nodes[user].props)


def test_passrole_instance_profile_targets_admin_role():
    builder = GraphBuilder("skyark-ip")
    deployer = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/deployer",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/deployer",
            "name": "deployer",
            "provider": "aws",
            "is_caller": True,
        },
    )
    admin = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/AdminRole",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/AdminRole",
            "name": "AdminRole",
            "provider": "aws",
        },
    )
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="pol:aa",
        props={
            "principal_arn": "arn:aws:iam::1:role/AdminRole",
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "actions": ["*"],
        },
    )
    for action in ("iam:PassRole", "iam:AddRoleToInstanceProfile"):
        builder.add_edge(
            src_id=deployer,
            rel_type="CONTROLS",
            dst_id=admin,
            props={"action": action},
        )
    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    assert any(e.pattern.id == "aws-iam-passrole-instance-profile" for e in edges)
    assert any(e.dst_id == admin for e in edges)
    enrich_high_value_targets(builder, provider=CloudProvider.AWS)
    enrich_shadow_admins(builder, provider=CloudProvider.AWS)
    assert is_shadow_admin(builder.snapshot.nodes[deployer].props)
