"""Shadow admin detection tests."""

from __future__ import annotations

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.attack.high_value import enrich_high_value_targets
from samoyed.attack.outcomes import ADMIN_OUTCOME_TYPE
from samoyed.attack.shadow_admin import enrich_shadow_admins
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import is_shadow_admin, summarize_markings
from samoyed.path_engine.search import find_attack_paths


def test_passrole_to_admin_role_marks_shadow_admin():
    builder = GraphBuilder("shadow-passrole")
    deployer = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ec2Deployer-role",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/ec2Deployer-role",
            "name": "ec2Deployer-role",
            "provider": "aws",
            "is_caller": True,
        },
    )
    admin_role = builder.add_concept_node(
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
        native_id="pol:admin",
        props={
            "principal_arn": "arn:aws:iam::1:role/AdminRole",
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "actions": ["*"],
        },
    )
    builder.add_edge(
        src_id=deployer,
        rel_type="CONTROLS",
        dst_id=admin_role,
        props={"action": "iam:PassRole"},
    )
    builder.add_edge(
        src_id=deployer,
        rel_type="EXECUTES",
        dst_id=admin_role,
        props={"action": "ec2:RunInstances"},
    )

    apply_attack_analysis(builder, provider=CloudProvider.AWS)
    enrich_high_value_targets(builder, provider=CloudProvider.AWS)
    stats = enrich_shadow_admins(builder, provider=CloudProvider.AWS)

    assert stats["shadow_admins"] >= 1
    assert is_shadow_admin(builder.snapshot.nodes[deployer].props)
    assert not is_shadow_admin(builder.snapshot.nodes[admin_role].props)

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=deployer,
        target_resource_type=ADMIN_OUTCOME_TYPE,
        max_depth=4,
    )
    assert paths
    summary = summarize_markings(builder.snapshot)
    assert summary["shadow_admin_count"] >= 1


def test_attach_user_policy_without_admin_policy_is_shadow():
    builder = GraphBuilder("shadow-attach")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/helpdesk",
        props={
            "native_kind": "User",
            "arn": "arn:aws:iam::1:user/helpdesk",
            "name": "helpdesk",
            "provider": "aws",
            "is_caller": True,
        },
    )
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=user,
        props={"action": "iam:AttachUserPolicy"},
    )
    apply_attack_analysis(builder, provider=CloudProvider.AWS)
    enrich_high_value_targets(builder, provider=CloudProvider.AWS)
    enrich_shadow_admins(builder, provider=CloudProvider.AWS)

    assert is_shadow_admin(builder.snapshot.nodes[user].props)
    assert builder.snapshot.nodes[user].props.get("high_value_kind") not in {
        "administrator-policy",
        "administrator-wildcard",
        "iam-full-access",
        "account-root",
    }


def test_blatant_admin_is_not_shadow():
    builder = GraphBuilder("not-shadow")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/Admin",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/Admin",
            "name": "Admin",
            "provider": "aws",
        },
    )
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="pol:aa",
        props={
            "principal_arn": "arn:aws:iam::1:role/Admin",
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "actions": ["*"],
        },
    )
    builder.add_edge(src_id=role, rel_type="CONTROLS", dst_id=role, props={"action": "*"})
    enrich_high_value_targets(builder, provider=CloudProvider.AWS)
    enrich_shadow_admins(builder, provider=CloudProvider.AWS)
    assert not is_shadow_admin(builder.snapshot.nodes[role].props)
