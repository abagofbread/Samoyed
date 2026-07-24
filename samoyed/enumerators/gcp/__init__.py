from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.capabilities import gcp_member_native_id, gcp_role_to_actions, map_gcp_role
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.gcp import sa_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.gcp.helpers import call_gcp
from samoyed.enumerators.gcp.compute import GcpComputeEnumerator
from samoyed.enumerators.gcp.wif import GcpWifEnumerator


def _resource_concept(resource_type: str | None) -> ConceptType:
    if resource_type == "GCPSecret":
        return ConceptType.SECRET_STORE
    if resource_type == "GCSBucket":
        return ConceptType.DATA_STORE
    if resource_type == "ServiceAccount":
        return ConceptType.IDENTITY
    return ConceptType.DATA_STORE


class GcpIdentityEnumerator:
    concept = ConceptType.IDENTITY
    name = "gcp-identity"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        project = ctx.scope.properties.get("project_id", "")
        caller_id = ctx.scope.properties.get("native_id", "")
        caller_email = ctx.scope.properties.get("email", "")

        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.GCP,
            native_id=caller_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": "ServiceAccount" if "serviceaccount" in caller_id else "User",
                "email": caller_email,
                "is_caller": True,
                "display_name": caller_email,
            },
            evidence=Evidence("gcp:caller", {"email": caller_email}),
            confidence=ConfidenceType.EXPLICIT,
        )

        iam = cred.client("iam")  # type: ignore[attr-defined]
        parent = f"projects/{project}"
        resp = call_gcp(
            ctx,
            operation="iam.serviceAccounts.list",
            call=lambda: list(iam.list_service_accounts(request={"parent": parent})),
        )
        if not resp:
            return
        for sa in resp:
            email = sa.email
            native_id = sa_native_id(email)
            yield ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=CloudProvider.GCP,
                native_id=native_id,
                scope_id=ctx.scope.scope_id,
                properties={
                    "native_kind": "ServiceAccount",
                    "email": email,
                    "display_name": email,
                    "name": sa.name,
                },
                evidence=Evidence("iam.serviceAccounts.list", {"email": email}),
            )


class GcpEntitlementEnumerator:
    concept = ConceptType.ENTITLEMENT
    name = "gcp-entitlement"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        project = ctx.scope.properties.get("project_id", "")
        rm = cred.client("resourcemanager")  # type: ignore[attr-defined]
        policy = call_gcp(
            ctx,
            operation="resourcemanager.projects.getIamPolicy",
            call=lambda: rm.get_iam_policy(request={"resource": f"projects/{project}"}),
        )
        if not policy:
            return

        iam = cred.client("iam")  # type: ignore[attr-defined]
        service_accounts = call_gcp(
            ctx,
            operation="iam.serviceAccounts.list",
            call=lambda: list(iam.list_service_accounts(request={"parent": f"projects/{project}"})),
        ) or []
        sa_records = [(sa.email, sa.name) for sa in service_accounts]

        yield from self._policy_artifacts(
            ctx, policy, project, "project", service_accounts=sa_records
        )
        for email, name in sa_records:
            sa_policy = call_gcp(
                ctx,
                operation="iam.serviceAccounts.getIamPolicy",
                call=lambda resource=name: iam.get_iam_policy(request={"resource": resource}),
            )
            if sa_policy:
                yield from self._policy_artifacts(
                    ctx,
                    sa_policy,
                    project,
                    f"serviceaccount:{email}",
                    target_service_account=email,
                )

        # Hierarchy IAM is supplementary: project IAM remains useful if folder/org
        # discovery permissions are absent.
        yield from self._hierarchy_artifacts(ctx, cred, project)

    def _policy_artifacts(
        self,
        ctx: EnumContext,
        policy: object,
        project: str,
        scope_name: str,
        *,
        service_accounts: list[tuple[str, str]] | None = None,
        target_service_account: str | None = None,
    ) -> Iterator[ConceptArtifact]:
        for idx, binding in enumerate(policy.bindings):  # type: ignore[attr-defined]
            role = binding.role
            mapping = map_gcp_role(role)
            if not mapping:
                continue
            members = list(binding.members)
            edges: list[ConceptEdge] = []
            for member in members:
                member_id = gcp_member_native_id(member)
                rel = mapping.capability.value
                targets: list[str]
                if target_service_account:
                    targets = [sa_native_id(target_service_account)]
                    rel = "CAN_ASSUME_ROLE"
                elif mapping.resource_type == "ServiceAccount":
                    rel = "CAN_ASSUME_ROLE"
                    targets = [sa_native_id(email) for email, _name in service_accounts or []]
                    if not targets:
                        targets = ["gcp:serviceaccount:*"]
                else:
                    rtype = mapping.resource_type or "Resource"
                    targets = [f"{rtype}:*"]
                for target_id in targets:
                    edges.append(
                        ConceptEdge(
                            rel_type=rel,
                            src_native_id=member_id,
                            target_native_id=target_id,
                            target_concept_type=(
                                ConceptType.IDENTITY
                                if rel == "CAN_ASSUME_ROLE"
                                else _resource_concept(mapping.resource_type)
                            ),
                            props={
                                "role": role,
                                "member": member,
                                "mechanisms": sorted(gcp_role_to_actions(role)),
                                "iam_scope": scope_name,
                            },
                            confidence=(
                                ConfidenceType.EXPLICIT
                                if "*" not in target_id
                                else ConfidenceType.WILDCARD
                            ),
                        )
                    )
            if edges:
                yield ConceptArtifact(
                    concept_type=ConceptType.TRUST if target_service_account else ConceptType.ENTITLEMENT,
                    provider=CloudProvider.GCP,
                    native_id=f"gcp:{scope_name}:binding:{project}:{idx}:{role}",
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "role": role,
                        "members": members,
                        "target_service_account": target_service_account,
                    },
                    evidence=Evidence(
                        "iam.serviceAccounts.getIamPolicy"
                        if target_service_account
                        else "resourcemanager.projects.getIamPolicy",
                        {"role": role, "scope": scope_name},
                    ),
                    edges=edges,
                )

    def _hierarchy_artifacts(
        self, ctx: EnumContext, cred: object, project: str
    ) -> Iterator[ConceptArtifact]:
        """Best-effort folder/org IAM; callers commonly lack hierarchy visibility."""
        try:
            projects = cred.client("resourcemanager")  # type: ignore[attr-defined]
            project_obj = call_gcp(
                ctx,
                operation="resourcemanager.projects.get",
                call=lambda: projects.get_project(name=f"projects/{project}"),
            )
            parent = getattr(project_obj, "parent", "") if project_obj else ""
            while parent:
                if parent.startswith("folders/"):
                    folders = cred.client("folders")  # type: ignore[attr-defined]
                    folder = call_gcp(
                        ctx,
                        operation="resourcemanager.folders.get",
                        call=lambda resource=parent: folders.get_folder(name=resource),
                    )
                    policy = call_gcp(
                        ctx,
                        operation="resourcemanager.folders.getIamPolicy",
                        call=lambda resource=parent: folders.get_iam_policy(request={"resource": resource}),
                    )
                    if policy:
                        yield from self._policy_artifacts(ctx, policy, project, parent)
                    parent = getattr(folder, "parent", "") if folder else ""
                    continue
                if parent.startswith("organizations/"):
                    orgs = cred.client("organizations")  # type: ignore[attr-defined]
                    policy = call_gcp(
                        ctx,
                        operation="resourcemanager.organizations.getIamPolicy",
                        call=lambda resource=parent: orgs.get_iam_policy(request={"resource": resource}),
                    )
                    if policy:
                        yield from self._policy_artifacts(ctx, policy, project, parent)
                break
        except Exception:
            return


class GcpStorageEnumerator:
    concept = ConceptType.DATA_STORE
    name = "gcp-storage"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        project = ctx.scope.properties.get("project_id", "")
        storage = cred.client("storage")  # type: ignore[attr-defined]
        buckets = call_gcp(ctx, operation="storage.buckets.list", call=lambda: list(storage.list_buckets()))
        if not buckets:
            return
        for bucket in buckets:
            name = bucket.name
            native_id = f"GCSBucket:{name}"
            edges: list[ConceptEdge] = []
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in getattr(policy, "bindings", []) or []:
                    role = getattr(binding, "role", "") or ""
                    members = list(getattr(binding, "members", []) or [])
                    public = any(m in {"allUsers", "allAuthenticatedUsers"} for m in members)
                    if not public:
                        continue
                    rel = "READS"
                    if "admin" in role or "writer" in role.lower() or "objectAdmin" in role:
                        rel = "WRITES"
                    edges.append(
                        ConceptEdge(
                            rel_type=rel,
                            src_native_id="network:internet",
                            target_native_id=native_id,
                            target_concept_type=ConceptType.DATA_STORE,
                            props={
                                "role": role,
                                "member": "allUsers" if "allUsers" in members else "allAuthenticatedUsers",
                                "mechanism": "public-gcs",
                            },
                            confidence=ConfidenceType.EXPLICIT,
                        )
                    )
            except Exception:
                pass
            yield ConceptArtifact(
                concept_type=ConceptType.DATA_STORE,
                provider=CloudProvider.GCP,
                native_id=native_id,
                scope_id=ctx.scope.scope_id,
                properties={
                    "resource_type": "GCSBucket",
                    "bucket_name": name,
                    "project_id": project,
                    "display_name": name,
                    "public_access": bool(edges),
                },
                evidence=Evidence("storage.buckets.list", {"bucket": name}),
                edges=edges,
            )


class GcpSecretEnumerator:
    concept = ConceptType.SECRET_STORE
    name = "gcp-secrets"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        project = ctx.scope.properties.get("project_id", "")
        sm = cred.client("secretmanager")  # type: ignore[attr-defined]
        parent = f"projects/{project}"
        secrets = call_gcp(
            ctx,
            operation="secretmanager.secrets.list",
            call=lambda: list(sm.list_secrets(request={"parent": parent})),
        )
        if not secrets:
            return
        for secret in secrets:
            name = secret.name
            short = name.split("/")[-1]
            native_id = f"GCPSecret:{name}"
            yield ConceptArtifact(
                concept_type=ConceptType.SECRET_STORE,
                provider=CloudProvider.GCP,
                native_id=native_id,
                scope_id=ctx.scope.scope_id,
                properties={
                    "resource_type": "GCPSecret",
                    "name": short,
                    "full_name": name,
                    "display_name": short,
                },
                evidence=Evidence("secretmanager.secrets.list", {"name": name}),
            )


GCP_ENUMERATORS = [
    GcpIdentityEnumerator(),
    GcpEntitlementEnumerator(),
    GcpComputeEnumerator(),
    GcpStorageEnumerator(),
    GcpSecretEnumerator(),
    GcpWifEnumerator(),
]
