from __future__ import annotations

import json
from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.capabilities import map_aws_action
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.contracts import ConceptEnumerator
from samoyed.enumerators.runner import paginate_call
from samoyed.graph.resource_scope import resolve_policy_resource


def _iter_statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement", [])
    if isinstance(stmt, dict):
        return [stmt]
    return list(stmt)


class AwsIdentityEnumerator:
    concept = ConceptType.IDENTITY
    name = "aws-identity"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        ident = cred.get_caller_identity()  # type: ignore[attr-defined]
        arn = ident["Arn"]
        account = ident["Account"]
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=arn,
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": _principal_kind(arn),
                "account_id": account,
                "arn": arn,
                "is_caller": True,
            },
            evidence=Evidence("sts:GetCallerIdentity", {"arn": arn}),
            confidence=ConfidenceType.EXPLICIT,
        )

        # Account root is a permanent crown jewel even when the caller is not root.
        root_arn = f"arn:aws:iam::{account}:root"
        if arn != root_arn:
            yield ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=CloudProvider.AWS,
                native_id=root_arn,
                scope_id=ctx.scope.scope_id,
                properties={
                    "native_kind": "Root",
                    "account_id": account,
                    "arn": root_arn,
                    "name": "root",
                    "display_name": f"Account root ({account})",
                    "blatant_high_value": True,
                },
                evidence=Evidence("sts:GetCallerIdentity", {"account": account, "synthetic": "account-root"}),
            )

        iam = cred.client("iam")  # type: ignore[attr-defined]
        for op, fn, kind in [
            ("iam:ListRoles", lambda: iam.list_roles(), "Role"),
            ("iam:ListUsers", lambda: iam.list_users(), "User"),
        ]:
            resp = paginate_call(ctx, operation=op, call=fn)
            if not resp:
                continue
            key = "Roles" if kind == "Role" else "Users"
            for item in resp.get(key, []):
                item_arn = item["Arn"]
                yield ConceptArtifact(
                    concept_type=ConceptType.IDENTITY,
                    provider=CloudProvider.AWS,
                    native_id=item_arn,
                    scope_id=ctx.scope.scope_id,
                    properties={"native_kind": kind, "name": item["RoleName"] if kind == "Role" else item["UserName"], "arn": item_arn},
                    evidence=Evidence(op, {"arn": item_arn}),
                )


def _principal_kind(arn: str) -> str:
    if ":user/" in arn:
        return "User"
    if ":role/" in arn:
        return "Role"
    if ":root" in arn:
        return "Root"
    return "Unknown"


class AwsTrustEnumerator:
    concept = ConceptType.TRUST
    name = "aws-trust"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        iam = cred.client("iam")  # type: ignore[attr-defined]
        resp = paginate_call(ctx, operation="iam:ListRoles", call=lambda: iam.list_roles())
        if not resp:
            return
        for role in resp.get("Roles", []):
            role_arn = role["Arn"]
            trust = role.get("AssumeRolePolicyDocument") or {}
            if isinstance(trust, str):
                trust = json.loads(trust)
            for stmt in _iter_statements(trust):
                if stmt.get("Effect") != "Allow":
                    continue
                principals = _extract_principals(stmt.get("Principal"))
                for p in principals:
                    yield ConceptArtifact(
                        concept_type=ConceptType.TRUST,
                        provider=CloudProvider.AWS,
                        native_id=f"{p}->{role_arn}",
                        scope_id=ctx.scope.scope_id,
                        properties={"trust_doc": stmt, "role_arn": role_arn, "principal": p},
                        evidence=Evidence("iam:GetRole.trust", {"role": role_arn, "principal": p}),
                        edges=[
                            ConceptEdge(
                                rel_type="CAN_ASSUME_ROLE",
                                src_native_id=p,
                                target_native_id=role_arn,
                                target_concept_type=ConceptType.IDENTITY,
                                props={"role_arn": role_arn},
                            )
                        ],
                    )


def _extract_principals(principal: Any) -> list[str]:
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        out: list[str] = []
        for key, val in principal.items():
            if isinstance(val, list):
                out.extend(str(v) for v in val)
            else:
                out.append(f"{key}:{val}")
        return out
    return [str(principal)]


class AwsEntitlementEnumerator:
    concept = ConceptType.ENTITLEMENT
    name = "aws-entitlement"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        iam = cred.client("iam")  # type: ignore[attr-defined]
        resp = paginate_call(ctx, operation="iam:ListRoles", call=lambda: iam.list_roles())
        if not resp:
            return
        for role in resp.get("Roles", []):
            role_arn = role["Arn"]
            attached = paginate_call(
                ctx,
                operation="iam:ListAttachedRolePolicies",
                call=lambda r=role["RoleName"]: iam.list_attached_role_policies(RoleName=r),
            )
            if not attached:
                continue
            for pol in attached.get("AttachedPolicies", []):
                pol_meta = paginate_call(
                    ctx,
                    operation="iam:GetPolicy",
                    call=lambda p=pol["PolicyArn"]: iam.get_policy(PolicyArn=p),
                )
                if not pol_meta:
                    continue
                version = pol_meta["Policy"]["DefaultVersionId"]
                pol_arn = pol["PolicyArn"]
                doc_resp = paginate_call(
                    ctx,
                    operation="iam:GetPolicyVersion",
                    call=lambda: iam.get_policy_version(PolicyArn=pol_arn, VersionId=version),
                )
                if not doc_resp:
                    continue
                doc = doc_resp["PolicyVersion"]["Document"]
                if isinstance(doc, str):
                    doc = json.loads(doc)
                yield from _policy_to_artifacts(
                    ctx=ctx,
                    principal_arn=role_arn,
                    policy_arn=pol_arn,
                    policy_name=pol["PolicyName"],
                    doc=doc,
                )


def _policy_to_artifacts(
    *,
    ctx: EnumContext,
    principal_arn: str,
    policy_arn: str,
    policy_name: str,
    doc: dict[str, Any],
) -> Iterator[ConceptArtifact]:
    for idx, stmt in enumerate(_iter_statements(doc)):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        conf = ConfidenceType.WILDCARD if "*" in actions or "*" in resources else ConfidenceType.EXPLICIT
        if stmt.get("Condition"):
            conf = ConfidenceType.UNKNOWN_CONDITIONS
        stmt_id = f"{policy_arn}:stmt{idx}"
        edges: list[ConceptEdge] = []
        for action in actions:
            mapping = map_aws_action(action)
            if not mapping:
                continue
            for resource in resources:
                resource_type = mapping.resource_type or "UnresolvedResource"
                resource_id, scope = resolve_policy_resource(resource, resource_type)
                edges.append(
                    ConceptEdge(
                        rel_type=mapping.capability.value,
                        src_native_id=principal_arn,
                        target_native_id=resource_id,
                        target_concept_type=_resource_concept(scope.resource_type or resource_type),
                        props={
                            "action": action,
                            "resource": resource,
                            "resource_type": scope.resource_type,
                            "scope_canonical_id": scope.canonical_id,
                            **({"path_prefix": scope.path_prefix} if scope.path_prefix else {}),
                        },
                        confidence=conf,
                    )
                )
        yield ConceptArtifact(
            concept_type=ConceptType.ENTITLEMENT,
            provider=CloudProvider.AWS,
            native_id=stmt_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "policy_arn": policy_arn,
                "policy_name": policy_name,
                "principal_arn": principal_arn,
                "actions": list(actions),
                "resources": list(resources),
                "sid": stmt.get("Sid"),
            },
            evidence=Evidence("iam:GetPolicyVersion", {"policy_arn": policy_arn, "statement_index": idx}),
            confidence=conf,
            edges=edges,
        )


def _resource_concept(resource_type: str) -> ConceptType:
    if resource_type in {"Secret", "SSMParameter"}:
        return ConceptType.SECRET_STORE
    if resource_type in {"S3Bucket", "ECRRepository"}:
        return ConceptType.DATA_STORE if resource_type == "S3Bucket" else ConceptType.REGISTRY_STORE
    if resource_type in {"Role", "User", "IAM", "Policy"}:
        return ConceptType.IDENTITY if resource_type != "Policy" else ConceptType.ENTITLEMENT
    return ConceptType.DATA_STORE


class AwsComputeEnumerator:
    concept = ConceptType.RUNTIME_BINDING
    name = "aws-compute"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        from samoyed.enumerators.aws.ecs import enumerate_ecs_topology
        from samoyed.enumerators.aws.runtime_bindings import (
            enumerate_ec2_instances,
            enumerate_lambda_functions,
        )

        yield from enumerate_ec2_instances(ctx)
        yield from enumerate_lambda_functions(ctx)
        yield from enumerate_ecs_topology(ctx)


class AwsStorageEnumerator:
    concept = ConceptType.DATA_STORE
    name = "aws-storage"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        from samoyed.enumerators.aws.tags import environment_from_tags, normalize_tag_map

        cred = ctx.credentials
        s3 = cred.client("s3")  # type: ignore[attr-defined]
        resp = paginate_call(ctx, operation="s3:ListBuckets", call=lambda: s3.list_buckets())
        if not resp:
            return
        for bucket in resp.get("Buckets", []):
            name = bucket["Name"]
            native_id = f"S3Bucket:{name}"
            tags_resp = paginate_call(
                ctx,
                operation="s3:GetBucketTagging",
                call=lambda n=name: s3.get_bucket_tagging(Bucket=n),
            )
            tags = normalize_tag_map((tags_resp or {}).get("TagSet"))
            env = environment_from_tags(tags)
            props: dict[str, Any] = {"resource_type": "S3Bucket", "bucket_name": name}
            if tags:
                props["tags"] = tags
            if env:
                props["environment"] = env
            yield ConceptArtifact(
                concept_type=ConceptType.DATA_STORE,
                provider=CloudProvider.AWS,
                native_id=native_id,
                scope_id=ctx.scope.scope_id,
                properties=props,
                evidence=Evidence("s3:ListBuckets", {"bucket": name}),
            )


class AwsSecretEnumerator:
    concept = ConceptType.SECRET_STORE
    name = "aws-secrets"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        sm = cred.client("secretsmanager")  # type: ignore[attr-defined]
        resp = paginate_call(ctx, operation="secretsmanager:ListSecrets", call=lambda: sm.list_secrets())
        if resp:
            for secret in resp.get("SecretList", []):
                arn = secret["ARN"]
                native_id = f"Secret:{arn}"
                yield ConceptArtifact(
                    concept_type=ConceptType.SECRET_STORE,
                    provider=CloudProvider.AWS,
                    native_id=native_id,
                    scope_id=ctx.scope.scope_id,
                    properties={"resource_type": "Secret", "name": secret.get("Name"), "arn": arn},
                    evidence=Evidence("secretsmanager:ListSecrets", {"arn": arn}),
                )
        ssm = cred.client("ssm")  # type: ignore[attr-defined]
        sresp = paginate_call(
            ctx,
            operation="ssm:DescribeParameters",
            call=lambda: ssm.describe_parameters(MaxResults=50),
        )
        if sresp:
            for param in sresp.get("Parameters", []):
                name = param["Name"]
                native_id = f"SSMParameter:{name}"
                yield ConceptArtifact(
                    concept_type=ConceptType.SECRET_STORE,
                    provider=CloudProvider.AWS,
                    native_id=native_id,
                    scope_id=ctx.scope.scope_id,
                    properties={"resource_type": "SSMParameter", "parameter_name": name},
                    evidence=Evidence("ssm:DescribeParameters", {"name": name}),
                )


def _access_analyzer_enumerator() -> ConceptEnumerator:
    from samoyed.enumerators.aws.access_analyzer import AwsAccessAnalyzerEnumerator

    return AwsAccessAnalyzerEnumerator()


def _cloudtrail_enumerator() -> ConceptEnumerator:
    from samoyed.enumerators.aws.cloudtrail_observed import AwsCloudTrailObservedEnumerator

    return AwsCloudTrailObservedEnumerator()


def _cicd_enumerator() -> ConceptEnumerator:
    from samoyed.enumerators.aws.cicd import AwsCicdEnumerator

    return AwsCicdEnumerator()


def _static_hosting_enumerator() -> ConceptEnumerator:
    from samoyed.enumerators.aws.static_hosting import AwsStaticHostingEnumerator

    return AwsStaticHostingEnumerator()


AWS_ENUMERATORS: list[ConceptEnumerator] = [
    AwsIdentityEnumerator(),
    AwsTrustEnumerator(),
    AwsEntitlementEnumerator(),
    AwsComputeEnumerator(),
    AwsStorageEnumerator(),
    AwsSecretEnumerator(),
    _cicd_enumerator(),
    _static_hosting_enumerator(),
    _access_analyzer_enumerator(),
    _cloudtrail_enumerator(),
]
