from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.azure import mi_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.azure.helpers import call_azure


class AzureIdentityEnumerator:
    concept = ConceptType.IDENTITY
    name = "azure-identity"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        caller_id = ctx.scope.properties.get("native_id", "")
        sub = ctx.scope.properties.get("subscription_id", "")

        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AZURE,
            native_id=caller_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": "ServicePrincipal" if "serviceprincipal" in caller_id else "User",
                "is_caller": True,
                "subscription_id": sub,
                "display_name": caller_id,
            },
            evidence=Evidence("azure:caller", {"native_id": caller_id}),
            confidence=ConfidenceType.EXPLICIT,
        )

        yield from _list_user_assigned_identities(ctx, sub)


def _list_user_assigned_identities(
    ctx: EnumContext, subscription_id: str
) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    try:
        msi = cred.client("msi")  # type: ignore[attr-defined]
    except ImportError:
        return

    identities = call_azure(
        ctx,
        operation="msi.userAssignedIdentities.listBySubscription",
        call=lambda: list(msi.user_assigned_identities.list_by_subscription()),
    )
    if not identities:
        return

    for identity in identities:
        principal_id = getattr(identity, "principal_id", None)
        client_id = getattr(identity, "client_id", None)
        name = getattr(identity, "name", None) or ""
        if not principal_id:
            continue
        native_id = mi_native_id(str(principal_id))
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AZURE,
            native_id=native_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": "ManagedIdentity",
                "principal_id": str(principal_id),
                "client_id": str(client_id) if client_id else None,
                "name": name,
                "display_name": name or native_id,
                "subscription_id": subscription_id,
                "resource_id": getattr(identity, "id", None),
            },
            evidence=Evidence(
                "msi.userAssignedIdentities.listBySubscription",
                {"name": name, "principal_id": str(principal_id)},
            ),
        )
