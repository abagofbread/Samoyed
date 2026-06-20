from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.capabilities import gcp_member_native_id, map_gcp_role
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.gcp import sa_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.gcp.helpers import call_gcp
from samoyed.enumerators.gcp.compute import GcpComputeEnumerator


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

        for idx, binding in enumerate(policy.bindings):
            role = binding.role
            mapping = map_gcp_role(role)
            if not mapping:
                continue
            members = list(binding.members)
            edges: list[ConceptEdge] = []
            for member in members:
                member_id = gcp_member_native_id(member)
                rel = mapping.capability.value
                if mapping.resource_type == "ServiceAccount":
                    rel = "CAN_ASSUME_ROLE"
                    target_id = "gcp:serviceaccount:*"
                    target_concept = ConceptType.IDENTITY
                else:
                    rtype = mapping.resource_type or "Resource"
                    target_id = f"{rtype}:*"
                    target_concept = _resource_concept(mapping.resource_type)
                edges.append(
                    ConceptEdge(
                        rel_type=rel,
                        src_native_id=member_id,
                        target_native_id=target_id,
                        target_concept_type=target_concept,
                        props={"role": role, "member": member},
                        confidence=ConfidenceType.WILDCARD,
                    )
                )

            if not edges:
                continue

            yield ConceptArtifact(
                concept_type=ConceptType.ENTITLEMENT,
                provider=CloudProvider.GCP,
                native_id=f"gcp:binding:{project}:{idx}",
                scope_id=ctx.scope.scope_id,
                properties={"role": role, "members": members},
                evidence=Evidence("resourcemanager.projects.getIamPolicy", {"role": role}),
                edges=edges,
            )


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
                },
                evidence=Evidence("storage.buckets.list", {"bucket": name}),
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
]
