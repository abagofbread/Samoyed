from __future__ import annotations

import json
import re
from typing import Any

from botocore.exceptions import ClientError

from samoyed.cloud.capabilities import map_aws_action
from samoyed.credentials.aws import AwsCredential, is_access_denied

CONCEPT_FOR_RESOURCE = {
    "S3Bucket": "DataStore",
    "Secret": "SecretStore",
    "LambdaFunction": "RuntimeBinding",
    "EC2Instance": "RuntimeBinding",
    "Role": "Identity",
}


def collect_iam_report(credentials: AwsCredential) -> dict[str, Any]:
    """
    Build a Samoyed iam-report document from live AWS API responses.

    Intended for Samoyed client agents that run with compromised credentials and
    ship recon results back to the server — no hand-authored topology.
    """
    ident = credentials.get_caller_identity()
    account_id = ident["Account"]
    caller_arn = ident["Arn"]

    identities: dict[str, dict[str, Any]] = {}
    resources: dict[str, dict[str, Any]] = {}
    grants: list[dict[str, Any]] = []

    _identity(
        identities,
        arn=caller_arn,
        name=_name_from_arn(caller_arn),
        kind=_kind_from_arn(caller_arn),
        is_caller=True,
    )

    iam = credentials.client("iam")
    if ":user/" in caller_arn:
        username = caller_arn.split("/")[-1]
        _collect_user_policies(iam, username, caller_arn, identities, resources, grants)
        _collect_user_trust_from_policies(iam, username, caller_arn, identities, grants)

    _collect_listed_principals(iam, identities, grants)
    assumable_roles = {
        g["to"]
        for g in grants
        if g.get("from") == caller_arn and g.get("rel") == "CAN_ASSUME_ROLE" and ":role/" in str(g.get("to", ""))
    }
    _collect_assumable_role_policies(iam, assumable_roles, identities, resources, grants)
    _collect_buckets(credentials, resources, grants, caller_arn)
    _collect_secrets(credentials, resources, grants, caller_arn)
    _collect_lambda(credentials, identities, resources, grants)
    _collect_ec2(credentials, identities, resources, grants)
    _collect_execution_role_policies(iam, grants, identities, resources)

    return {
        "account_id": account_id,
        "caller_arn": caller_arn,
        "source": "samoyed-client",
        "collected_via": "live-aws-api",
        "identities": list(identities.values()),
        "resources": list(resources.values()),
        "grants": grants,
    }


def _collect_user_policies(
    iam: Any,
    username: str,
    caller_arn: str,
    identities: dict[str, dict[str, Any]],
    resources: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
) -> None:
    try:
        inline = iam.list_user_policies(UserName=username)
    except ClientError as exc:
        if is_access_denied(exc):
            return
        raise

    for policy_name in inline.get("PolicyNames", []):
        doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)["PolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        _policy_grants(doc, caller_arn, policy_name, identities, resources, grants)

    try:
        attached = iam.list_attached_user_policies(UserName=username)
    except ClientError as exc:
        if is_access_denied(exc):
            return
        raise

    for pol in attached.get("AttachedPolicies", []):
        pol_arn = pol["PolicyArn"]
        version = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version)["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        _policy_grants(doc, caller_arn, pol["PolicyName"], identities, resources, grants)


def _collect_user_trust_from_policies(
    iam: Any,
    username: str,
    caller_arn: str,
    identities: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
) -> None:
    """If inline policies reference role ARNs for AssumeRole, record CAN_ASSUME_ROLE grants."""
    try:
        inline = iam.list_user_policies(UserName=username)
    except ClientError:
        return
    for policy_name in inline.get("PolicyNames", []):
        doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)["PolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        for stmt in _statements(doc):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if not any(a in ("sts:AssumeRole", "iam:AssumeRole", "*") or str(a).startswith("sts:Assume") for a in actions):
                continue
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources:
                if ":role/" in resource:
                    _identity(identities, arn=resource, name=resource.split("/")[-1], kind="Role")
                    grants.append(
                        {
                            "from": caller_arn,
                            "to": resource,
                            "rel": "CAN_ASSUME_ROLE",
                            "action": "sts:AssumeRole",
                            "policy": policy_name,
                        }
                    )


def _collect_listed_principals(
    iam: Any,
    identities: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
) -> None:
    for list_op, key, kind in (("list_users", "Users", "User"), ("list_roles", "Roles", "Role")):
        try:
            resp = getattr(iam, list_op)()
        except ClientError as exc:
            if is_access_denied(exc):
                continue
            raise
        for item in resp.get(key, []):
            arn = item["Arn"]
            name = item.get("UserName") or item.get("RoleName") or arn
            _identity(identities, arn=arn, name=name, kind=kind)
            if kind == "Role":
                trust = item.get("AssumeRolePolicyDocument") or {}
                if isinstance(trust, str):
                    trust = json.loads(trust)
                for stmt in _statements(trust):
                    if stmt.get("Effect") != "Allow":
                        continue
                    for principal in _principals(stmt.get("Principal")):
                        if principal.startswith("arn:"):
                            _identity(identities, arn=principal, name=_name_from_arn(principal), kind=_kind_from_arn(principal))
                            grants.append(
                                {
                                    "from": principal,
                                    "to": arn,
                                    "rel": "CAN_ASSUME_ROLE",
                                    "action": "sts:AssumeRole",
                                    "source": "trust-policy",
                                }
                            )


def _collect_assumable_role_policies(
    iam: Any,
    starter_roles: set[str],
    identities: dict[str, dict[str, Any]],
    resources: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
    *,
    max_depth: int = 3,
) -> None:
    """Expand grants for roles the caller can assume (and chained assumes), for multi-hop paths."""
    queue = list(starter_roles)
    seen: set[str] = set()
    depth = 0
    while queue and depth < max_depth:
        next_queue: list[str] = []
        for role_arn in queue:
            if role_arn in seen:
                continue
            seen.add(role_arn)
            role_name = role_arn.split("/")[-1]
            _identity(identities, arn=role_arn, name=role_name, kind="Role")
            try:
                inline = iam.list_role_policies(RoleName=role_name)
            except ClientError as exc:
                if is_access_denied(exc):
                    continue
                raise
            for policy_name in inline.get("PolicyNames", []):
                try:
                    doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
                except ClientError as exc:
                    if is_access_denied(exc):
                        continue
                    raise
                if isinstance(doc, str):
                    doc = json.loads(doc)
                before = len(grants)
                _policy_grants(doc, role_arn, policy_name, identities, resources, grants)
                for grant in grants[before:]:
                    if grant.get("rel") == "CAN_ASSUME_ROLE" and ":role/" in str(grant.get("to", "")):
                        next_queue.append(str(grant["to"]))
        queue = next_queue
        depth += 1


def _collect_execution_role_policies(
    iam: Any,
    grants: list[dict[str, Any]],
    identities: dict[str, dict[str, Any]],
    resources: dict[str, dict[str, Any]],
) -> None:
    """Expand inline policies for roles bound to EC2/Lambda via EXECUTES_AS."""
    execution_roles = {
        g["to"]
        for g in grants
        if g.get("rel") == "EXECUTES_AS" and ":role/" in str(g.get("to", ""))
    }
    if execution_roles:
        _collect_assumable_role_policies(iam, execution_roles, identities, resources, grants)


def _collect_buckets(
    credentials: AwsCredential,
    resources: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
    caller_arn: str,
) -> None:
    s3 = credentials.client("s3")
    try:
        resp = s3.list_buckets()
    except ClientError as exc:
        if is_access_denied(exc):
            return
        raise
    for bucket in resp.get("Buckets", []):
        name = bucket["Name"]
        native_id = f"S3Bucket:{name}"
        resources[native_id] = {
            "id": native_id,
            "concept": "DataStore",
            "type": "S3Bucket",
            "name": name,
            "display_name": name,
        }
        grants.append(
            {
                "from": caller_arn,
                "to": native_id,
                "rel": "READS",
                "action": "s3:ListBuckets",
                "source": "s3:ListBuckets",
            }
        )


def _collect_secrets(
    credentials: AwsCredential,
    resources: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
    caller_arn: str,
) -> None:
    sm = credentials.client("secretsmanager")
    try:
        resp = sm.list_secrets()
    except ClientError as exc:
        if is_access_denied(exc):
            return
        raise
    for secret in resp.get("SecretList", []):
        arn = secret["ARN"]
        native_id = f"Secret:{arn}"
        resources[native_id] = {
            "id": native_id,
            "concept": "SecretStore",
            "type": "Secret",
            "name": secret.get("Name"),
            "display_name": secret.get("Name") or arn,
        }
        grants.append(
            {
                "from": caller_arn,
                "to": native_id,
                "rel": "READS",
                "action": "secretsmanager:ListSecrets",
                "source": "secretsmanager:ListSecrets",
            }
        )


def _collect_lambda(
    credentials: AwsCredential,
    identities: dict[str, dict[str, Any]],
    resources: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
) -> None:
    lam = credentials.client("lambda")
    try:
        resp = lam.list_functions()
    except ClientError as exc:
        if is_access_denied(exc):
            return
        raise
    for fn in resp.get("Functions", []):
        fn_arn = fn["FunctionArn"]
        native_id = f"LambdaFunction:{fn_arn}"
        resources[native_id] = {
            "id": native_id,
            "concept": "RuntimeBinding",
            "type": "LambdaFunction",
            "name": fn.get("FunctionName"),
            "display_name": fn.get("FunctionName") or fn_arn,
        }
        role_arn = fn.get("Role")
        if role_arn:
            _identity(identities, arn=role_arn, name=_name_from_arn(role_arn), kind="Role")
            grants.append(
                {
                    "from": native_id,
                    "to": role_arn,
                    "rel": "EXECUTES_AS",
                    "action": "lambda:InvokeFunction",
                    "source": "lambda:ListFunctions",
                }
            )


def _collect_ec2(
    credentials: AwsCredential,
    identities: dict[str, dict[str, Any]],
    resources: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
) -> None:
    ec2 = credentials.client("ec2")
    iam = credentials.client("iam")
    try:
        resp = ec2.describe_instances()
    except ClientError as exc:
        if is_access_denied(exc):
            return
        raise

    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            state = inst.get("State", {}).get("Name")
            if state in {"terminated", "shutting-down"}:
                continue
            iid = inst["InstanceId"]
            account = credentials.get_caller_identity()["Account"]
            region = credentials.region or "us-east-1"
            arn = f"arn:aws:ec2:{region}:{account}:instance/{iid}"
            native_id = f"EC2Instance:{arn}"
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            name = tags.get("Name", iid)
            instance_type = inst.get("InstanceType", "")

            props: dict[str, Any] = {
                "id": native_id,
                "concept": "RuntimeBinding",
                "type": "EC2Instance",
                "name": name,
                "display_name": f"{name} ({iid})",
                "instance_id": iid,
                "instance_type": instance_type,
                "state": state,
            }
            if tags.get("samoyed:ssrf_vulnerable", "").lower() == "true":
                props["ssrf_vulnerable"] = True
                props["display_name"] = f"{name} ({iid}, IMDS)"
            if tags.get("samoyed:internet_exposed", "").lower() == "true":
                props["has_public_reach"] = True
                props["exposure_level"] = "internet"
            compute_class = tags.get("samoyed:compute_class")
            if compute_class:
                props["compute_class"] = compute_class
            if tags.get("samoyed:gpu_accelerated", "").lower() == "true" or instance_type.startswith(
                ("g4", "g5", "p3", "p4", "p5")
            ):
                props["gpu_accelerated"] = True
                props.setdefault("compute_class", "gpu")

            resources[native_id] = props

            profile = inst.get("IamInstanceProfile") or {}
            profile_name = profile.get("Arn", "").split("/")[-1] if profile.get("Arn") else None
            role_arn = _instance_profile_role_arn(iam, profile_name)
            if role_arn:
                _identity(identities, arn=role_arn, name=_name_from_arn(role_arn), kind="Role")
                grants.append(
                    {
                        "from": native_id,
                        "to": role_arn,
                        "rel": "EXECUTES_AS",
                        "action": "ec2:DescribeInstances",
                        "source": "instance-profile",
                    }
                )
                props["execution_role_arn"] = role_arn


def _instance_profile_role_arn(iam: Any, profile_name: str | None) -> str | None:
    if not profile_name:
        return None
    try:
        resp = iam.get_instance_profile(InstanceProfileName=profile_name)
    except ClientError:
        return None
    roles = resp.get("InstanceProfile", {}).get("Roles") or []
    if not roles:
        return None
    return roles[0].get("Arn")


def _policy_grants(
    doc: dict[str, Any],
    principal_arn: str,
    policy_name: str,
    identities: dict[str, dict[str, Any]],
    resources: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
) -> None:
    for stmt in _statements(doc):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources_raw = stmt.get("Resource", [])
        if isinstance(resources_raw, str):
            resources_raw = [resources_raw]
        for action in actions:
            mapping = map_aws_action(str(action))
            if not mapping:
                continue
            rel = mapping.capability.value
            for resource in resources_raw:
                target_id, resource_meta = _resolve_resource_target(str(resource), mapping.resource_type)
                if resource_meta:
                    resources[target_id] = resource_meta
                if ":role/" in str(resource):
                    _identity(identities, arn=str(resource), name=_name_from_arn(str(resource)), kind="Role")
                grants.append(
                    {
                        "from": principal_arn,
                        "to": target_id,
                        "rel": "CAN_ASSUME_ROLE" if rel == "EXECUTES" and ":role/" in str(resource) else rel,
                        "action": action,
                        "policy": policy_name,
                    }
                )


def _resolve_resource_target(
    resource: str,
    resource_type: str | None,
) -> tuple[str, dict[str, Any] | None]:
    if resource.startswith("arn:aws:secretsmanager:"):
        native_id = f"Secret:{resource}"
        return native_id, {
            "id": native_id,
            "concept": "SecretStore",
            "type": "Secret",
            "name": resource.split(":")[-1],
            "display_name": resource,
        }
    if resource.startswith("arn:aws:s3:") or resource.startswith("arn:aws:s3:::"):
        match = re.search(r":::([^/*]+)", resource) or re.search(r"bucket/([^/*]+)", resource)
        name = match.group(1) if match else resource
        native_id = f"S3Bucket:{name}"
        return native_id, {
            "id": native_id,
            "concept": "DataStore",
            "type": "S3Bucket",
            "name": name,
            "display_name": name,
        }
    if ":role/" in resource:
        return resource, None
    if resource_type == "S3Bucket":
        name = resource.strip("*").split("/")[0]
        native_id = f"S3Bucket:{name}"
        return native_id, {
            "id": native_id,
            "concept": "DataStore",
            "type": "S3Bucket",
            "name": name,
            "display_name": name,
        }
    return resource, None


def _statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement", [])
    if isinstance(stmt, dict):
        return [stmt]
    return list(stmt)


def _principals(principal: Any) -> list[str]:
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        out: list[str] = []
        for key in ("AWS", "Service", "Federated"):
            val = principal.get(key)
            if isinstance(val, str):
                out.append(val)
            elif isinstance(val, list):
                out.extend(str(v) for v in val)
        return out
    return [str(principal)]


def _identity(
    identities: dict[str, dict[str, Any]],
    *,
    arn: str,
    name: str,
    kind: str,
    is_caller: bool = False,
) -> None:
    identities[arn] = {
        "arn": arn,
        "name": name,
        "kind": kind,
        "display_name": name,
        **({"is_caller": True} if is_caller else {}),
    }


def _name_from_arn(arn: str) -> str:
    if "/" in arn:
        return arn.split("/")[-1]
    return arn.split(":")[-1]


def _kind_from_arn(arn: str) -> str:
    if ":user/" in arn:
        return "User"
    if ":role/" in arn:
        return "Role"
    return "Identity"
