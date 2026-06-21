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
    _collect_buckets(credentials, resources, grants, caller_arn)
    _collect_secrets(credentials, resources, grants, caller_arn)
    _collect_lambda(credentials, identities, resources, grants)

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
