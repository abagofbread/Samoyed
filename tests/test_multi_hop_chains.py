from __future__ import annotations

"""
Multi-hop attack-path tests modeled on published AWS privesc research.

References:
- AWS STS role chaining (deployment / audit tier assume-role ladders)
- Rhino Security Labs AWS IAM Privilege Escalation (Lambda PassRole + CreateFunction + Invoke)
- Host pivot → cached SSO → cloud role (HackTricks / red-team playbooks)
"""

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.sample_host import build_sample_host_graph
from samoyed.path_engine.explain import explain_path
from samoyed.path_engine.search import find_attack_paths, get_blast_radius


def _build_aws_deployment_role_chain() -> tuple[object, str, str]:
    """
    Enterprise role-chaining ladder (common in CI/CD + break-glass designs):

    contractor → SecurityAudit → DevOpsDeploy → OrgAdmin → prod secret

    Mirrors layered AssumeRole policies where each tier can only assume the next.
    """
    builder = GraphBuilder("role-chain-session")
    contractor = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:user/contractor",
        props={
            "native_kind": "User",
            "is_caller": True,
            "arn": "arn:aws:iam::111111111111:user/contractor",
            "display_name": "contractor",
        },
    )
    audit = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/SecurityAudit",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/SecurityAudit"},
    )
    deploy = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/DevOpsDeploy",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/DevOpsDeploy"},
    )
    admin = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/OrganizationAccountAccessRole",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::111111111111:role/OrganizationAccountAccessRole",
        },
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db",
        props={"resource_type": "Secret", "name": "prod-db"},
    )

    builder.add_edge(src_id=contractor, rel_type="CAN_ASSUME_ROLE", dst_id=audit, props={"confidence": "explicit"})
    builder.add_edge(src_id=audit, rel_type="CAN_ASSUME_ROLE", dst_id=deploy, props={"confidence": "explicit"})
    builder.add_edge(src_id=deploy, rel_type="CAN_ASSUME_ROLE", dst_id=admin, props={"confidence": "explicit"})
    builder.add_edge(src_id=admin, rel_type="READS", dst_id=secret, props={"confidence": "explicit"})

    for node_id in (contractor, audit, deploy, admin, secret):
        builder.link_session(node_id)

    apply_attack_analysis(builder, provider=CloudProvider.AWS)
    return builder.snapshot, contractor, secret


def _build_rhino_lambda_passrole_chain() -> tuple[object, str, str]:
    """
    Rhino Security Labs method: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
    on a privileged execution role, after assuming a CI/CD role.
    """
    builder = GraphBuilder("lambda-chain-session")
    contractor = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:user/contractor",
        props={"native_kind": "User", "is_caller": True, "arn": "arn:aws:iam::111111111111:user/contractor"},
    )
    ci_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/CIDeploy",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/CIDeploy"},
    )
    admin = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/admin",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/admin"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db",
        props={"resource_type": "Secret", "name": "prod-db"},
    )

    builder.add_edge(src_id=contractor, rel_type="CAN_ASSUME_ROLE", dst_id=ci_role, props={"confidence": "explicit"})
    # Entitlements on the assumed CI role — avoid a direct CONTROLS shortcut to admin.
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="policy:ci-deploy-lambda-privesc",
        props={
            "principal_arn": "arn:aws:iam::111111111111:role/CIDeploy",
            "actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        },
    )
    builder.add_edge(src_id=admin, rel_type="READS", dst_id=secret, props={"confidence": "explicit"})

    for node_id in (contractor, ci_role, admin, secret):
        builder.link_session(node_id)

    # Privesc patterns apply to identities reachable after AssumeRole, not only the entry caller.
    apply_attack_analysis(
        builder,
        provider=CloudProvider.AWS,
        start_node_ids=[contractor, ci_role],
    )
    return builder.snapshot, contractor, secret


def test_aws_role_chaining_four_hops_to_secret():
    """contractor → 3× AssumeRole tiers → READS prod secret (4 hops)."""
    snapshot, start, secret = _build_aws_deployment_role_chain()

    paths = find_attack_paths(
        snapshot,
        start_node_id=start,
        target_concept="SecretStore",
        max_depth=8,
    )

    assert len(paths) >= 1
    best = paths[0]
    assert len(best.steps) == 4
    assert [s.rel_type for s in best.steps] == [
        "CAN_ASSUME_ROLE",
        "CAN_ASSUME_ROLE",
        "CAN_ASSUME_ROLE",
        "READS",
    ]
    assert best.node_ids[0] == start
    assert best.node_ids[-1] == secret
    assert best.score > 0.5

    explanation = explain_path(snapshot, best)
    assert "4 hop" in explanation["summary"]
    assert explanation["steps"][0]["relationship"] == "CAN_ASSUME_ROLE"


def test_rhino_lambda_passrole_three_hop_chain():
    """Assume CI role → Lambda privesc (PassRole) → READS secret (3 hops)."""
    snapshot, start, secret = _build_rhino_lambda_passrole_chain()

    paths = find_attack_paths(
        snapshot,
        start_node_id=start,
        target_concept="SecretStore",
        max_depth=8,
    )

    assert len(paths) >= 1
    best = paths[0]
    assert len(best.steps) >= 3
    rels = [s.rel_type for s in best.steps]
    assert rels[0] == "CAN_ASSUME_ROLE"
    assert "CAN_PRIVESC_TO" in rels
    assert rels[-1] == "READS"
    assert best.node_ids[-1] == secret

    privesc_step = next(s for s in best.steps if s.rel_type == "CAN_PRIVESC_TO")
    assert "Lambda create + invoke" in (privesc_step.evidence.get("pattern_name") or "")


def test_host_compromise_lambda_pivot_four_hop_chain():
    """
    Compromised laptop → harvest dev creds → Lambda code takeover → execution role → secret.

    Longest path in sample-host uses Rhino-style lambda:UpdateFunctionCode against
    internal-tool, which EXECUTES_AS the admin role.
    """
    snapshot = build_sample_host_graph("host-chain-test")
    host = next(
        n.node_id
        for n in snapshot.nodes.values()
        if n.props.get("native_kind") == "CompromisedHost"
    )
    secret = next(
        n.node_id
        for n in snapshot.nodes.values()
        if n.props.get("resource_type") == "Secret"
    )

    paths = find_attack_paths(snapshot, start_node_id=host, target_concept="SecretStore", max_depth=10)
    assert paths, "expected a path from compromised host to SecretStore"

    longest = [p for p in paths if len(p.steps) == max(len(p.steps) for p in paths)]
    assert len(longest[0].steps) >= 4
    rels = [s.rel_type for s in longest[0].steps]
    assert rels[0] == "CAN_PRIVESC_TO"
    assert "CONTROLS" in rels
    assert "EXECUTES_AS" in rels
    assert rels[-1] == "READS"
    assert longest[0].node_ids[-1] == secret

    privesc_step = next(s for s in longest[0].steps if s.rel_type == "CAN_PRIVESC_TO")
    assert "token theft" in (privesc_step.evidence.get("pattern_name") or "").lower() or "credential" in (
        privesc_step.evidence.get("pattern_name") or ""
    ).lower()


def test_host_compromise_sso_cache_three_hop_chain():
    """Shorter path: ~/.aws/sso/cache → dev user → assume admin role → prod secret."""
    snapshot = build_sample_host_graph("host-chain-test")
    host = next(
        n.node_id
        for n in snapshot.nodes.values()
        if n.props.get("native_kind") == "CompromisedHost"
    )

    paths = find_attack_paths(snapshot, start_node_id=host, target_concept="SecretStore", max_depth=10)
    sso_paths = [
        p
        for p in paths
        if [s.rel_type for s in p.steps] == ["CAN_PRIVESC_TO", "CAN_ASSUME_ROLE", "READS"]
        or [s.rel_type for s in p.steps] == ["CAN_STEAL_CREDS_FROM", "CAN_ASSUME_ROLE", "READS"]
        or [s.rel_type for s in p.steps] == ["STORES_CREDS_FOR", "CAN_ASSUME_ROLE", "READS"]
    ]
    assert sso_paths, "expected SSO-cache → assume-role → secret chain"
    assert len(sso_paths[0].steps) == 3
    assert sso_paths[0].steps[-1].rel_type == "READS"


def test_blast_radius_surfaces_longest_role_chain():
    snapshot, start, _secret = _build_aws_deployment_role_chain()
    paths = get_blast_radius(snapshot, start_node_id=start, max_depth=8)
    secret_paths = [p for p in paths if p.target_match.get("concept_type") == "SecretStore"]
    assert secret_paths
    assert max(len(p.steps) for p in secret_paths) >= 4
