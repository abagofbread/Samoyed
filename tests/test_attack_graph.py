from __future__ import annotations

from samoyed.attack.analyzer import (
    action_matches,
    apply_attack_analysis,
    collect_principal_actions,
    has_required_actions,
)
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.path_engine.search import find_attack_paths, get_blast_radius


def test_action_wildcard_matching():
    assert action_matches("iam:*", "iam:PassRole")
    assert action_matches("*", "s3:ListBuckets")
    assert not action_matches("s3:GetObject", "iam:PassRole")


def test_iam_attach_policy_privesc_edge():
    builder = GraphBuilder("attack-test")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/leaked",
        props={"is_caller": True, "native_kind": "User"},
    )
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=user,
        props={"action": "iam:AttachUserPolicy"},
    )

    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    assert len(edges) == 1
    assert edges[0].pattern.id == "aws-iam-attach-user-policy"
    privesc = [e for e in builder.snapshot.edges if e.rel_type == "CAN_PRIVESC_TO"]
    assert len(privesc) == 1
    assert privesc[0].src_id == user
    assert privesc[0].dst_id != user
    assert builder.snapshot.nodes[privesc[0].dst_id].props.get("concept_type") == "AttackOutcome"
    assert privesc[0].props.get("attack_outcome") == "administrator-access"
    assert any(n.props.get("concept_type") == "AttackOutcome" for n in builder.snapshot.nodes.values())


def test_find_attack_paths_to_admin_outcome_via_edge():
    builder = GraphBuilder("attack-test")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/leaked",
        props={"is_caller": True, "native_kind": "User"},
    )
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=user,
        props={"action": "iam:PutUserPolicy"},
    )
    apply_attack_analysis(builder, provider=CloudProvider.AWS)

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=user,
        target_concept="AttackOutcome",
        max_depth=2,
    )
    assert len(paths) == 1
    assert paths[0].target_match.get("concept_type") == "AttackOutcome"
    assert paths[0].target_match.get("virtual") is not True
    assert paths[0].steps[0].rel_type == "CAN_PRIVESC_TO"
    assert paths[0].steps[0].dst_id != user
    assert paths[0].steps[0].evidence.get("attack_outcome") == "administrator-access"


def test_lambda_passrole_privesc_to_role():
    builder = GraphBuilder("attack-test")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/leaked",
        props={"is_caller": True, "native_kind": "User"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:role/admin",
        props={"native_kind": "Role"},
    )
    for action in ("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"):
        builder.add_edge(src_id=user, rel_type="CONTROLS", dst_id=role, props={"action": action})

    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    assert any(e.pattern.id == "aws-lambda-create-invoke" for e in edges)
    privesc = [e for e in builder.snapshot.edges if e.rel_type == "CAN_PRIVESC_TO"]
    assert any(e.dst_id != user for e in privesc)


def test_blast_radius_includes_admin_outcome():
    builder = GraphBuilder("attack-test")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/leaked",
        props={"is_caller": True, "native_kind": "User"},
    )
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=user,
        props={"action": "iam:PutUserPolicy"},
    )
    apply_attack_analysis(builder, provider=CloudProvider.AWS)

    paths = get_blast_radius(builder.snapshot, start_node_id=user, max_depth=4)
    assert any(p.target_match.get("concept_type") == "AttackOutcome" for p in paths)


def test_assume_role_then_secret_still_found():
    builder = GraphBuilder("attack-test")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/leaked",
        props={"is_caller": True},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:role/admin",
        props={"native_kind": "Role"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:prod",
        props={"resource_type": "Secret"},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role)
    builder.add_edge(src_id=role, rel_type="READS", dst_id=secret)
    apply_attack_analysis(builder, provider=CloudProvider.AWS)

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=user,
        target_concept="SecretStore",
        max_depth=4,
    )
    assert len(paths) == 1


def test_collect_actions_from_entitlement_node():
    builder = GraphBuilder("attack-test")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/leaked",
        props={"is_caller": True},
    )
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="policy:stmt:1",
        props={
            "principal_arn": "arn:aws:iam::123:user/leaked",
            "actions": ["iam:CreateAccessKey", "s3:ListBuckets"],
        },
    )
    actions = collect_principal_actions(builder.snapshot, user)
    assert has_required_actions(actions, frozenset({"iam:CreateAccessKey"}))
