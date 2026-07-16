"""Privesc target resolution must not invent account-wide false positives."""

from __future__ import annotations

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder


def test_update_function_configuration_without_lambda_exec_role_emits_nothing():
    """SecretsManagerReadWrite grants UFC on SecretsManager* — must not fan out to all roles."""
    builder = GraphBuilder("ufc-fp")
    task = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-task-role",
        props={
            "native_kind": "Role",
            "arn": "arn:aws:iam::1:role/ecs-task-role",
            "is_caller": True,
        },
    )
    # Noise roles that the old fallback would target.
    for name in ("ec2Deployer-role", "ecs-instance-role", "AWSServiceRoleForECS"):
        arn = (
            f"arn:aws:iam::1:role/aws-service-role/ecs.amazonaws.com/{name}"
            if "ServiceRole" in name
            else f"arn:aws:iam::1:role/{name}"
        )
        builder.add_concept_node(
            concept_type=ConceptType.IDENTITY,
            native_id=arn,
            props={"native_kind": "Role", "arn": arn, "name": name},
        )
    # Capability edge matching SecretsManagerReadWrite — no EXECUTES_AS on the function.
    lam = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="Lambda:arn:aws:lambda:*:*:function:SecretsManager*",
        props={"resource_type": "Lambda"},
    )
    builder.add_edge(
        src_id=task,
        rel_type="WRITES",
        dst_id=lam,
        props={"action": "lambda:UpdateFunctionConfiguration"},
    )

    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    ufc = [e for e in edges if e.pattern.id == "aws-lambda-update-configuration-layer"]
    assert ufc == [], f"expected no UFC privesc edges, got {[(e.dst_id, e.pattern.id) for e in ufc]}"


def test_update_function_code_targets_only_controlled_lambda_exec_role():
    builder = GraphBuilder("ufc-ok")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/dev",
        props={"native_kind": "User", "arn": "arn:aws:iam::1:user/dev", "is_caller": True},
    )
    noise = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/unrelated",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/unrelated"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/lambda-admin",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/lambda-admin"},
    )
    fn = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:tool",
        props={"resource_type": "LambdaFunction"},
    )
    builder.add_edge(src_id=fn, rel_type="EXECUTES_AS", dst_id=role)
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=fn,
        props={"action": "lambda:UpdateFunctionCode"},
    )

    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    code_edges = [e for e in edges if e.pattern.id == "aws-lambda-update-code"]
    assert len(code_edges) == 1
    assert code_edges[0].dst_id == role
    assert all(e.dst_id != noise for e in code_edges)
