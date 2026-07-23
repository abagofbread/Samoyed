from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.aws.config_refs import config_reads_edges
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
    env: dict[str, str] | None = None,
    image_uri: str | None = None,
    evidence_op: str,
    evidence_details: dict[str, Any],
) -> ConceptArtifact:
    edges: list[ConceptEdge] = []
    if role_arn:
        edges.append(executes_as_edge(role_arn, resource_type="LambdaFunction", function_arn=fn_arn))
    edges.extend(
        config_reads_edges(
            source="lambda-config",
            env=env,
            image_uri=image_uri,
            extra_blobs=[extra_props.get("kms_key_arn")] if extra_props and extra_props.get("kms_key_arn") else None,
        )
    )
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
    image_uri = ((fn.get("ImageConfigResponse") or {}).get("ImageUri")) or None
    if not image_uri and fn.get("PackageType") == "Image":
        image_uri = fn.get("CodeSha256")  # not a URI — ignore non-URI

    return lambda_function_artifact(
        ctx,
        fn_arn=fn_arn,
        function_name=fn["FunctionName"],
        role_arn=role,
        env=dict(env) if env else None,
        image_uri=image_uri if image_uri and "/" in str(image_uri) else None,
        extra_props={
            "env_var_keys": env_keys,
            "runtime": fn.get("Runtime"),
            "has_env_vars": bool(env_keys),
            "package_type": fn.get("PackageType"),
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
        env: dict[str, str] = {}
        image_uri: str | None = None

        cfg = paginate_call(
            ctx,
            operation="lambda:GetFunctionConfiguration",
            call=lambda name=fn["FunctionName"]: lam.get_function_configuration(FunctionName=name),
        )
        if cfg:
            role = cfg.get("Role") or role
            env = dict((cfg.get("Environment") or {}).get("Variables") or {})
            if env:
                extra["env_var_keys"] = sorted(env.keys())
                extra["has_env_vars"] = True
            if cfg.get("KMSKeyArn"):
                extra["kms_key_arn"] = cfg["KMSKeyArn"]
            extra["package_type"] = cfg.get("PackageType") or fn.get("PackageType")
            # Container-image Lambdas — Code.ImageUri on GetFunction, not always on config
            img = (cfg.get("ImageConfigResponse") or {}) if isinstance(cfg.get("ImageConfigResponse"), dict) else {}
            if img.get("ImageUri"):
                image_uri = img["ImageUri"]

        # Prefer GetFunction for ImageUri when PackageType is Image
        if (extra.get("package_type") or fn.get("PackageType")) == "Image" and not image_uri:
            full = paginate_call(
                ctx,
                operation="lambda:GetFunction",
                call=lambda name=fn["FunctionName"]: lam.get_function(FunctionName=name),
            )
            if full:
                image_uri = ((full.get("Code") or {}).get("ImageUri")) or image_uri

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

        vpc = (cfg or {}).get("VpcConfig") or fn.get("VpcConfig") or {}
        if vpc.get("SubnetIds") or vpc.get("SecurityGroupIds") or vpc.get("VpcId"):
            extra["vpc_id"] = vpc.get("VpcId")
            extra["subnet_ids"] = list(vpc.get("SubnetIds") or [])
            extra["sg_ids"] = list(vpc.get("SecurityGroupIds") or [])
            extra["account_id"] = ctx.scope.properties.get("account_id") or (
                ctx.scope.scope_id.split(":")[-1] if ctx.scope.scope_id else None
            )

        yield lambda_function_artifact(
            ctx,
            fn_arn=fn_arn,
            function_name=fn["FunctionName"],
            role_arn=role,
            env=env or None,
            image_uri=image_uri,
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
            sgs = [
                str(g.get("GroupId"))
                for g in (inst.get("SecurityGroups") or [])
                if g.get("GroupId")
            ]
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
                    "vpc_id": inst.get("VpcId"),
                    "subnet_ids": [inst["SubnetId"]] if inst.get("SubnetId") else [],
                    "private_ips": [inst["PrivateIpAddress"]] if inst.get("PrivateIpAddress") else [],
                    "public_ip": inst.get("PublicIpAddress"),
                    "sg_ids": sgs,
                    "account_id": ctx.scope.properties.get("account_id")
                    or (ctx.scope.scope_id.split(":")[-1] if ctx.scope.scope_id else None),
                },
                evidence=Evidence("ec2:DescribeInstances", {"instance_id": iid}),
                edges=edges,
            )


def enumerate_ecs_task_roles(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    """Delegate to full ECS topology + escape enumeration."""
    from samoyed.enumerators.aws.ecs import enumerate_ecs_topology

    yield from enumerate_ecs_topology(ctx)
