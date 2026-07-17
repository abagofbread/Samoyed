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


def test_ufc_does_not_target_other_lambdas_execution_roles():
    """Account has two Lambdas; UFC only on the one the principal CONTROLS."""
    builder = GraphBuilder("ufc-scoped")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/dev",
        props={"native_kind": "User", "arn": "arn:aws:iam::1:user/dev", "is_caller": True},
    )
    role_a = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/fn-a-role",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/fn-a-role"},
    )
    role_b = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/fn-b-role",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/fn-b-role"},
    )
    fn_a = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:a",
        props={"resource_type": "LambdaFunction"},
    )
    fn_b = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:b",
        props={"resource_type": "LambdaFunction"},
    )
    builder.add_edge(src_id=fn_a, rel_type="EXECUTES_AS", dst_id=role_a)
    builder.add_edge(src_id=fn_b, rel_type="EXECUTES_AS", dst_id=role_b)
    # Only mutate function A
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=fn_a,
        props={"action": "lambda:UpdateFunctionConfiguration"},
    )

    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    ufc = [e for e in edges if e.pattern.id == "aws-lambda-update-configuration-layer"]
    assert len(ufc) == 1
    assert ufc[0].dst_id == role_a
    assert all(e.dst_id != role_b for e in ufc)


def test_ufc_stub_pattern_resolves_matching_inventored_lambda():
    """WRITES Lambda:…SecretsManager* binds to inventored SecretsManager* function role."""
    builder = GraphBuilder("ufc-stub")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/task",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/task", "is_caller": True},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/sm-rotation",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/sm-rotation"},
    )
    noise_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/other-lambda",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/other-lambda"},
    )
    stub = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="Lambda:arn:aws:lambda:*:*:function:SecretsManager*",
        props={"resource_type": "Lambda"},
    )
    fn = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:SecretsManagerRotation",
        props={"resource_type": "LambdaFunction"},
    )
    other = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:billing",
        props={"resource_type": "LambdaFunction"},
    )
    builder.add_edge(src_id=fn, rel_type="EXECUTES_AS", dst_id=role)
    builder.add_edge(src_id=other, rel_type="EXECUTES_AS", dst_id=noise_role)
    builder.add_edge(
        src_id=user,
        rel_type="WRITES",
        dst_id=stub,
        props={
            "action": "lambda:UpdateFunctionConfiguration",
            "resource": "arn:aws:lambda:*:*:function:SecretsManager*",
            "resource_type": "LambdaFunction",
        },
    )

    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    ufc = [e for e in edges if e.pattern.id == "aws-lambda-update-configuration-layer"]
    assert len(ufc) == 1
    assert ufc[0].dst_id == role
    assert all(e.dst_id != noise_role for e in ufc)


def test_invoke_alone_does_not_hijack_execution_role():
    builder = GraphBuilder("ufc-invoke")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:user/reader",
        props={"native_kind": "User", "is_caller": True},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/fn-role",
        props={"native_kind": "Role"},
    )
    fn = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:1:function:tool",
        props={"resource_type": "LambdaFunction"},
    )
    builder.add_edge(src_id=fn, rel_type="EXECUTES_AS", dst_id=role)
    builder.add_edge(
        src_id=user,
        rel_type="EXECUTES",
        dst_id=fn,
        props={"action": "lambda:InvokeFunction"},
    )
    # Grant UFC action via entitlement but NO mutate edge to the function
    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="pol:reader",
        props={
            "principal_arn": "arn:aws:iam::1:user/reader",
            "actions": ["lambda:UpdateFunctionConfiguration", "lambda:InvokeFunction"],
        },
    )

    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    ufc = [e for e in edges if e.pattern.id == "aws-lambda-update-configuration-layer"]
    assert ufc == []
