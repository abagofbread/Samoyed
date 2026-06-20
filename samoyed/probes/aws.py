from __future__ import annotations

from typing import Any, Iterator

from botocore.exceptions import ClientError, EndpointConnectionError

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CapabilityType, CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.aws import is_access_denied
from samoyed.probes.models import ApiProbe, ProbeResult

AWS_PROBE_CATALOG: list[ApiProbe] = [
    ApiProbe("sts:GetCallerIdentity", "Resolve caller identity", CapabilityType.READS, high_value=True),
    ApiProbe("iam:ListUsers", "List IAM users", CapabilityType.READS, "Identity", concept_type="Identity"),
    ApiProbe("iam:ListRoles", "List IAM roles", CapabilityType.READS, "Identity", concept_type="Identity"),
    ApiProbe("iam:ListAttachedUserPolicies", "List user policies", CapabilityType.READS, "Policy"),
    ApiProbe("iam:ListAccessKeys", "List access keys", CapabilityType.READS, "Identity"),
    ApiProbe("s3:ListBuckets", "List S3 buckets", CapabilityType.READS, "S3Bucket", concept_type="DataStore", high_value=True),
    ApiProbe("s3:ListAllMyBuckets", "List all my buckets (legacy)", CapabilityType.READS, "S3Bucket", concept_type="DataStore"),
    ApiProbe(
        "secretsmanager:ListSecrets",
        "List Secrets Manager secrets",
        CapabilityType.READS,
        "Secret",
        concept_type="SecretStore",
        high_value=True,
    ),
    ApiProbe(
        "ssm:DescribeParameters",
        "List SSM parameters",
        CapabilityType.READS,
        "SSMParameter",
        concept_type="SecretStore",
        high_value=True,
    ),
    ApiProbe("ec2:DescribeInstances", "List EC2 instances", CapabilityType.READS, "EC2Instance", concept_type="RuntimeBinding"),
    ApiProbe("lambda:ListFunctions", "List Lambda functions", CapabilityType.READS, "LambdaFunction", concept_type="RuntimeBinding"),
    ApiProbe("dynamodb:ListTables", "List DynamoDB tables", CapabilityType.READS, "DynamoDBTable", concept_type="DataStore"),
    ApiProbe("rds:DescribeDBInstances", "List RDS instances", CapabilityType.READS, "RDSInstance", concept_type="DataStore", high_value=True),
    ApiProbe("eks:ListClusters", "List EKS clusters", CapabilityType.READS, "EKSCluster", concept_type="OrchestrationScope"),
    ApiProbe("ecr:DescribeRepositories", "List ECR repos", CapabilityType.READS, "ECRRepository", concept_type="RegistryStore"),
    ApiProbe("kms:ListKeys", "List KMS keys", CapabilityType.READS, "KMSKey", concept_type="SecretStore"),
    ApiProbe("sqs:ListQueues", "List SQS queues", CapabilityType.READS, "SQSQueue", concept_type="DataStore"),
    ApiProbe("sns:ListTopics", "List SNS topics", CapabilityType.READS, "SNSTopic", concept_type="DataStore"),
    ApiProbe("sts:AssumeRole", "Assume role (probe only — no target)", CapabilityType.EXECUTES, "Role", concept_type="Identity"),
]


def run_aws_probe(cred: Any, probe: ApiProbe) -> ProbeResult:
    try:
        return _dispatch_aws(cred, probe)
    except EndpointConnectionError as exc:
        return ProbeResult(probe.operation, "error", message=str(exc))
    except ClientError as exc:
        if is_access_denied(exc):
            code = exc.response.get("Error", {}).get("Code", "AccessDenied")
            return ProbeResult(probe.operation, "denied", error_code=code, message=str(exc))
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return ProbeResult(probe.operation, "error", error_code=code, message=str(exc))
    except Exception as exc:
        return ProbeResult(probe.operation, "error", message=str(exc))


def _dispatch_aws(cred: Any, probe: ApiProbe) -> ProbeResult:
    op = probe.operation

    if op == "sts:GetCallerIdentity":
        ident = cred.client("sts").get_caller_identity()
        return ProbeResult(op, "allowed", metadata={"identity": ident})

    if op == "sts:AssumeRole":
        # Probe-only: we don't know a role ARN; denied/error is expected unless misconfigured
        return ProbeResult(op, "denied", error_code="ProbeSkipped", message="AssumeRole requires a target role ARN")

    if op.startswith("iam:"):
        iam = cred.client("iam")
        if op == "iam:ListUsers":
            resp = iam.list_users(MaxItems=50)
            resources = [{"arn": u["Arn"], "name": u["UserName"]} for u in resp.get("Users", [])]
            return ProbeResult(op, "allowed", resources=resources)
        if op == "iam:ListRoles":
            resp = iam.list_roles(MaxItems=50)
            resources = [{"arn": r["Arn"], "name": r["RoleName"]} for r in resp.get("Roles", [])]
            return ProbeResult(op, "allowed", resources=resources)
        if op == "iam:ListAccessKeys":
            # Needs username — skip without identity
            return ProbeResult(op, "denied", error_code="ProbeSkipped", message="Requires username context")
        if op == "iam:ListAttachedUserPolicies":
            return ProbeResult(op, "denied", error_code="ProbeSkipped", message="Requires username context")

    if op.startswith("s3:"):
        s3 = cred.client("s3")
        resp = s3.list_buckets()
        resources = [{"name": b["Name"]} for b in resp.get("Buckets", [])]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "secretsmanager:ListSecrets":
        sm = cred.client("secretsmanager")
        resp = sm.list_secrets(MaxResults=50)
        resources = [{"arn": s["ARN"], "name": s.get("Name")} for s in resp.get("SecretList", [])]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "ssm:DescribeParameters":
        ssm = cred.client("ssm")
        resp = ssm.describe_parameters(MaxResults=50)
        resources = [{"name": p["Name"]} for p in resp.get("Parameters", [])]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "ec2:DescribeInstances":
        ec2 = cred.client("ec2")
        resp = ec2.describe_instances(MaxResults=50)
        resources = []
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                resources.append({"instance_id": inst["InstanceId"], "state": inst.get("State", {}).get("Name")})
        return ProbeResult(op, "allowed", resources=resources)

    if op == "lambda:ListFunctions":
        lam = cred.client("lambda")
        resp = lam.list_functions(MaxItems=50)
        resources = []
        for fn in resp.get("Functions", []):
            item: dict[str, Any] = {"arn": fn["FunctionArn"], "name": fn["FunctionName"]}
            role = fn.get("Role")
            try:
                cfg = lam.get_function_configuration(FunctionName=fn["FunctionName"])
                role = cfg.get("Role") or role
                env = (cfg.get("Environment") or {}).get("Variables") or {}
                if env:
                    item["env_var_keys"] = sorted(env.keys())
            except ClientError:
                pass
            if role:
                item["execution_role_arn"] = role
            resources.append(item)
        return ProbeResult(op, "allowed", resources=resources)

    if op == "dynamodb:ListTables":
        dd = cred.client("dynamodb")
        resp = dd.list_tables(Limit=50)
        resources = [{"name": n} for n in resp.get("TableNames", [])]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "rds:DescribeDBInstances":
        rds = cred.client("rds")
        resp = rds.describe_db_instances(MaxRecords=50)
        resources = [{"id": db["DBInstanceIdentifier"]} for db in resp.get("DBInstances", [])]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "eks:ListClusters":
        eks = cred.client("eks")
        resp = eks.list_clusters(maxResults=50)
        resources = [{"name": n} for n in resp.get("clusters", [])]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "ecr:DescribeRepositories":
        ecr = cred.client("ecr")
        resp = ecr.describe_repositories(maxResults=50)
        resources = [{"arn": r["repositoryArn"], "name": r["repositoryName"]} for r in resp.get("repositories", [])]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "kms:ListKeys":
        kms = cred.client("kms")
        resp = kms.list_keys(Limit=50)
        resources = [{"key_id": k["KeyId"]} for k in resp.get("Keys", [])]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "sqs:ListQueues":
        sqs = cred.client("sqs")
        resp = sqs.list_queues(MaxResults=50)
        urls = resp.get("QueueUrls") or []
        resources = [{"url": u} for u in urls]
        return ProbeResult(op, "allowed", resources=resources)

    if op == "sns:ListTopics":
        sns = cred.client("sns")
        resp = sns.list_topics()
        resources = [{"arn": t["TopicArn"]} for t in resp.get("Topics", [])]
        return ProbeResult(op, "allowed", resources=resources)

    return ProbeResult(op, "error", message=f"Unhandled probe: {op}")


def aws_probe_catalog(*, high_value_only: bool = False) -> list[ApiProbe]:
    if high_value_only:
        return [p for p in AWS_PROBE_CATALOG if p.high_value]
    return list(AWS_PROBE_CATALOG)


def artifacts_from_aws_probes(
    *,
    scope_id: str,
    caller_id: str,
    caller_kind: str,
    results: list[ProbeResult],
) -> Iterator[ConceptArtifact]:
    # Prefer STS identity when probe succeeded
    for result in results:
        if result.operation == "sts:GetCallerIdentity" and result.status == "allowed":
            ident = result.metadata.get("identity") or {}
            if ident.get("Arn"):
                caller_id = ident["Arn"]
                caller_kind = _principal_kind(caller_id)

    yield ConceptArtifact(
        concept_type=ConceptType.IDENTITY,
        provider=CloudProvider.AWS,
        native_id=caller_id,
        scope_id=scope_id,
        properties={
            "native_kind": caller_kind,
            "is_caller": True,
            "arn": caller_id,
            "discovered_via": "probe",
        },
        evidence=Evidence("probe:caller", {"source": "api_probe"}),
        confidence=ConfidenceType.EXPLICIT,
    )

    for result in results:
        if result.status != "allowed" or result.operation == "sts:GetCallerIdentity":
            continue
        probe = next((p for p in AWS_PROBE_CATALOG if p.operation == result.operation), None)
        if not probe:
            continue
        for resource in result.resources:
            native_id, concept, props = _aws_resource_artifact(probe, resource)
            if not native_id:
                continue
            extra_edges: list[ConceptEdge] = []
            if props.get("execution_role_arn"):
                role = props["execution_role_arn"]
                extra_edges.append(
                    ConceptEdge(
                        rel_type="EXECUTES_AS",
                        target_native_id=role,
                        target_concept_type=ConceptType.IDENTITY,
                        props={"function_arn": props.get("arn"), "inferred": True},
                    )
                )
            yield ConceptArtifact(
                concept_type=concept,
                provider=CloudProvider.AWS,
                native_id=native_id,
                scope_id=scope_id,
                properties={**props, "discovered_via": "probe"},
                evidence=Evidence(result.operation, resource),
                edges=[
                    ConceptEdge(
                        rel_type=probe.capability.value,
                        src_native_id=caller_id,
                        target_native_id=native_id,
                        target_concept_type=concept,
                        props={"operation": result.operation, "inferred": True},
                        confidence=ConfidenceType.EXPLICIT,
                    ),
                    *extra_edges,
                ],
            )


def _principal_kind(arn: str) -> str:
    if ":user/" in arn:
        return "User"
    if ":role/" in arn:
        return "Role"
    return "Unknown"


def _aws_resource_artifact(probe: ApiProbe, resource: dict[str, Any]) -> tuple[str | None, ConceptType, dict[str, Any]]:
    rtype = probe.resource_type or "Resource"
    if rtype == "S3Bucket":
        name = resource.get("name")
        return f"S3Bucket:{name}", ConceptType.DATA_STORE, {"resource_type": "S3Bucket", "bucket_name": name}
    if rtype == "Secret":
        arn = resource.get("arn", "")
        return f"Secret:{arn}", ConceptType.SECRET_STORE, {"resource_type": "Secret", "arn": arn, "name": resource.get("name")}
    if rtype == "SSMParameter":
        name = resource.get("name")
        return f"SSMParameter:{name}", ConceptType.SECRET_STORE, {"resource_type": "SSMParameter", "parameter_name": name}
    if rtype == "EC2Instance":
        iid = resource.get("instance_id")
        return f"EC2Instance:{iid}", ConceptType.RUNTIME_BINDING, {"resource_type": "EC2Instance", "instance_id": iid}
    if rtype == "LambdaFunction":
        arn = resource.get("arn")
        props: dict[str, Any] = {"resource_type": "LambdaFunction", "arn": arn}
        if resource.get("execution_role_arn"):
            props["execution_role_arn"] = resource["execution_role_arn"]
        if resource.get("env_var_keys"):
            props["env_var_keys"] = resource["env_var_keys"]
        return f"LambdaFunction:{arn}", ConceptType.RUNTIME_BINDING, props
    if rtype == "Identity" and resource.get("arn"):
        arn = resource["arn"]
        return arn, ConceptType.IDENTITY, {"native_kind": _principal_kind(arn), "arn": arn, "name": resource.get("name")}
    if rtype == "DynamoDBTable":
        name = resource.get("name")
        return f"DynamoDBTable:{name}", ConceptType.DATA_STORE, {"resource_type": "DynamoDBTable", "name": name}
    if rtype == "RDSInstance":
        rid = resource.get("id")
        return f"RDSInstance:{rid}", ConceptType.DATA_STORE, {"resource_type": "RDSInstance", "id": rid}
    if rtype == "ECRRepository":
        arn = resource.get("arn")
        return f"ECRRepository:{arn}", ConceptType.REGISTRY_STORE, {"resource_type": "ECRRepository", "arn": arn}
    if rtype == "KMSKey":
        kid = resource.get("key_id")
        return f"KMSKey:{kid}", ConceptType.SECRET_STORE, {"resource_type": "KMSKey", "key_id": kid}
    name = resource.get("name") or resource.get("arn") or resource.get("url")
    if name:
        return f"{rtype}:{name}", ConceptType.DATA_STORE, {"resource_type": rtype, **resource}
    return None, ConceptType.DATA_STORE, {}
