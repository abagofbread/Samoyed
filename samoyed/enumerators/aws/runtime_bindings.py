from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.runner import paginate_call


def executes_as_edge(role_arn: str, **props: Any) -> ConceptEdge:
    return ConceptEdge(
        rel_type="EXECUTES_AS",
        target_native_id=role_arn,
        target_concept_type=ConceptType.IDENTITY,
        props={"role_arn": role_arn, **props},
    )


def lambda_function_artifact(
    ctx: EnumContext,
    *,
    fn_arn: str,
    function_name: str,
    role_arn: str | None,
    extra_props: dict[str, Any] | None = None,
    evidence_op: str,
    evidence_details: dict[str, Any],
) -> ConceptArtifact:
    edges: list[ConceptEdge] = []
    if role_arn:
        edges.append(executes_as_edge(role_arn, resource_type="LambdaFunction", function_arn=fn_arn))
    props: dict[str, Any] = {
        "resource_type": "LambdaFunction",
        "function_name": function_name,
        "arn": fn_arn,
        "execution_role_arn": role_arn,
    }
    if extra_props:
        props.update(extra_props)
    return ConceptArtifact(
        concept_type=ConceptType.RUNTIME_BINDING,
        provider=CloudProvider.AWS,
        native_id=f"LambdaFunction:{fn_arn}",
        scope_id=ctx.scope.scope_id,
        properties=props,
        evidence=Evidence(evidence_op, evidence_details),
        edges=edges,
    )


def enrich_lambda_from_list(ctx: EnumContext, fn: dict[str, Any]) -> ConceptArtifact:
    fn_arn = fn["FunctionArn"]
    role = fn.get("Role")
    env_keys: list[str] = []
    env = (fn.get("Environment") or {}).get("Variables") or {}
    if env:
        env_keys = sorted(env.keys())

    return lambda_function_artifact(
        ctx,
        fn_arn=fn_arn,
        function_name=fn["FunctionName"],
        role_arn=role,
        extra_props={
            "env_var_keys": env_keys,
            "runtime": fn.get("Runtime"),
            "has_env_vars": bool(env_keys),
        },
        evidence_op="lambda:ListFunctions",
        evidence_details={"arn": fn_arn, "role": role},
    )


def enumerate_lambda_functions(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    lam = cred.client("lambda")  # type: ignore[attr-defined]
    lresp = paginate_call(ctx, operation="lambda:ListFunctions", call=lambda: lam.list_functions())
    if not lresp:
        return

    for fn in lresp.get("Functions", []):
        fn_arn = fn["FunctionArn"]
        role = fn.get("Role")
        extra: dict[str, Any] = {}

        cfg = paginate_call(
            ctx,
            operation="lambda:GetFunctionConfiguration",
            call=lambda name=fn["FunctionName"]: lam.get_function_configuration(FunctionName=name),
        )
        if cfg:
            role = cfg.get("Role") or role
            env = (cfg.get("Environment") or {}).get("Variables") or {}
            if env:
                extra["env_var_keys"] = sorted(env.keys())
                extra["has_env_vars"] = True
            if cfg.get("KMSKeyArn"):
                extra["kms_key_arn"] = cfg["KMSKeyArn"]

        policy = paginate_call(
            ctx,
            operation="lambda:GetPolicy",
            call=lambda name=fn["FunctionName"]: lam.get_policy(FunctionName=name),
        )
        if policy:
            extra["has_resource_policy"] = True

        urls = paginate_call(
            ctx,
            operation="lambda:ListFunctionUrlConfigs",
            call=lambda name=fn["FunctionName"]: lam.list_function_url_configs(FunctionName=name),
        )
        if urls and urls.get("FunctionUrlConfigs"):
            extra["function_urls"] = [u.get("FunctionUrl") for u in urls["FunctionUrlConfigs"]]
            extra["has_public_url"] = True

        yield lambda_function_artifact(
            ctx,
            fn_arn=fn_arn,
            function_name=fn["FunctionName"],
            role_arn=role,
            extra_props=extra,
            evidence_op="lambda:GetFunctionConfiguration",
            evidence_details={"arn": fn_arn, "role": role},
        )


def enumerate_ec2_instances(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    ec2 = cred.client("ec2")  # type: ignore[attr-defined]
    resp = paginate_call(ctx, operation="ec2:DescribeInstances", call=lambda: ec2.describe_instances())
    if not resp:
        return
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            iid = inst["InstanceId"]
            profile = inst.get("IamInstanceProfile") or {}
            profile_arn = profile.get("Arn")
            edges: list[ConceptEdge] = []
            if profile_arn:
                role_arn = profile_arn.replace("instance-profile/", "role/").replace(
                    ":instance-profile/", ":role/"
                )
                edges.append(
                    executes_as_edge(role_arn, resource_type="EC2Instance", instance_id=iid)
                )
            yield ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.AWS,
                native_id=f"EC2Instance:{iid}",
                scope_id=ctx.scope.scope_id,
                properties={
                    "resource_type": "EC2Instance",
                    "instance_id": iid,
                    "state": inst.get("State", {}).get("Name"),
                    "execution_role_arn": edges[0].target_native_id if edges else None,
                },
                evidence=Evidence("ec2:DescribeInstances", {"instance_id": iid}),
                edges=edges,
            )


def enumerate_ecs_task_roles(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    ecs = cred.client("ecs")  # type: ignore[attr-defined]
    clusters = paginate_call(ctx, operation="ecs:ListClusters", call=lambda: ecs.list_clusters())
    if not clusters:
        return
    for cluster_arn in clusters.get("clusterArns", []):
        tasks = paginate_call(
            ctx,
            operation="ecs:ListTasks",
            call=lambda c=cluster_arn: ecs.list_tasks(cluster=c),
        )
        if not tasks:
            continue
        for task_arn in tasks.get("taskArns", []):
            desc = paginate_call(
                ctx,
                operation="ecs:DescribeTasks",
                call=lambda c=cluster_arn, t=task_arn: ecs.describe_tasks(cluster=c, tasks=[t]),
            )
            if not desc:
                continue
            for task in desc.get("tasks", []):
                task_id = task.get("taskArn", task_arn)
                role_arn = (task.get("taskRoleArn") or task.get("executionRoleArn"))
                edges: list[ConceptEdge] = []
                if role_arn:
                    edges.append(executes_as_edge(role_arn, resource_type="ECSTask", task_arn=task_id))
                yield ConceptArtifact(
                    concept_type=ConceptType.RUNTIME_BINDING,
                    provider=CloudProvider.AWS,
                    native_id=f"ECSTask:{task_id}",
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "resource_type": "ECSTask",
                        "task_arn": task_id,
                        "cluster_arn": cluster_arn,
                        "execution_role_arn": role_arn,
                    },
                    evidence=Evidence("ecs:DescribeTasks", {"task_arn": task_id}),
                    edges=edges,
                )
