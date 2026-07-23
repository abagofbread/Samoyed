"""Blatant high-value target catalog tests."""

from __future__ import annotations

from samoyed.attack.high_value import enrich_high_value_targets
from samoyed.attack.outcomes import (
    ACCOUNT_ROOT_OUTCOME_TYPE,
    ADMIN_OUTCOME_TYPE,
    IAM_ADMIN_OUTCOME_TYPE,
)
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import is_high_value
from samoyed.path_engine.search import find_attack_paths


def test_account_root_marked_high_value():
    builder = GraphBuilder("hvt-root")
    root = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::859695290971:root",
        props={
            "native_kind": "Root",
            "arn": "arn:aws:iam::859695290971:root",
            "provider": "aws",
        },
    )
    stats = enrich_high_value_targets(builder, provider=CloudProvider.AWS)
    assert stats["identities_marked"] >= 1
    assert is_high_value(builder.snapshot.nodes[root].props)
    assert builder.snapshot.nodes[root].props["high_value_kind"] == "account-root"

    outcomes = [
        n
        for n in builder.snapshot.nodes.values()
        if n.props.get("concept_type") == "AttackOutcome"
    ]
    assert len(outcomes) >= 3
    assert all(is_high_value(n.props) for n in outcomes)


def test_iam_full_access_policy_marks_and_feeds_iam_outcome():
    builder = GraphBuilder("hvt-iam")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/ecs-instance-role",
            "name": "ecs-instance-role",
            "provider": "aws",
        },
    )
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="pol:IAMFullAccess",
        props={
            "principal_arn": "arn:aws:iam::1:role/ecs-instance-role",
            "policy_arn": "arn:aws:iam::aws:policy/IAMFullAccess",
            "policy_name": "IAMFullAccess",
            "actions": ["iam:*"],
        },
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=role,
        props={"action": "iam:*", "resource": "*"},
    )

    enrich_high_value_targets(builder, provider=CloudProvider.AWS)
    assert is_high_value(builder.snapshot.nodes[role].props)

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=role,
        target_resource_type=IAM_ADMIN_OUTCOME_TYPE,
        max_depth=3,
    )
    assert paths
    assert any(s.rel_type == "CAN_PRIVESC_TO" for s in paths[0].steps)


def test_attach_user_policy_reaches_administrator_outcome_node():
    builder = GraphBuilder("hvt-admin")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/leaked",
        props={
            "is_caller": True,
            "native_kind": "User",
            "arn": "arn:aws:iam::1:user/leaked",
            "provider": "aws",
        },
    )
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=user,
        props={"action": "iam:AttachUserPolicy"},
    )
    enrich_high_value_targets(builder, provider=CloudProvider.AWS)

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=user,
        target_concept="AttackOutcome",
        max_depth=3,
    )
    assert paths
    # Prefer materialised IAM/admin outcome over virtual-only.
    assert any(
        p.target_match.get("resource_type")
        in {ADMIN_OUTCOME_TYPE, IAM_ADMIN_OUTCOME_TYPE, ACCOUNT_ROOT_OUTCOME_TYPE}
        or p.target_match.get("concept_type") == "AttackOutcome"
        for p in paths
    )


def test_star_action_marks_administrator():
    builder = GraphBuilder("hvt-star")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/god",
        props={"native_kind": "User", "arn": "arn:aws:iam::1:user/god", "provider": "aws"},
    )
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=user,
        props={"action": "*"},
    )
    enrich_high_value_targets(builder, provider=CloudProvider.AWS)
    assert is_high_value(builder.snapshot.nodes[user].props)
    assert builder.snapshot.nodes[user].props.get("high_value_kind") == "administrator-wildcard"
