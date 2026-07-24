from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.azure.helpers import call_azure
from samoyed.enumerators.azure.targets import resource_group_from_id
from samoyed.network.model import INTERNET_NATIVE_ID


class AzureStorageEnumerator:
    concept = ConceptType.DATA_STORE
    name = "azure-storage"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        storage = cred.client("storage")  # type: ignore[attr-defined]
        accounts = call_azure(
            ctx,
            operation="storage.storageAccounts.list",
            call=lambda: list(storage.storage_accounts.list()),
        )
        if not accounts:
            return
        for account in accounts:
            name = account.name
            native_id = f"StorageAccount:{name}"
            public = _is_public_blob_access(account)
            edges: list[ConceptEdge] = []
            if public:
                for rel in ("READS", "WRITES"):
                    edges.append(
                        ConceptEdge(
                            rel_type=rel,
                            src_native_id=INTERNET_NATIVE_ID,
                            target_native_id=native_id,
                            target_concept_type=ConceptType.DATA_STORE,
                            props={
                                "mechanism": "public-blob",
                                "allow_blob_public_access": True,
                            },
                            confidence=ConfidenceType.EXPLICIT,
                        )
                    )
            yield ConceptArtifact(
                concept_type=ConceptType.DATA_STORE,
                provider=CloudProvider.AZURE,
                native_id=native_id,
                scope_id=ctx.scope.scope_id,
                properties={
                    "resource_type": "StorageAccount",
                    "account_name": name,
                    "display_name": name,
                    "resource_group": resource_group_from_id(getattr(account, "id", None)),
                    "public_access": public,
                    "allow_blob_public_access": public,
                },
                evidence=Evidence("storage.storageAccounts.list", {"account": name}),
                edges=edges,
            )


def _is_public_blob_access(account: object) -> bool:
    """True when allowBlobPublicAccess / public blob access is enabled."""
    props = getattr(account, "allow_blob_public_access", None)
    if props is True:
        return True
    # Some SDK versions nest under properties; also accept string "Enabled"
    nested = getattr(account, "properties", None)
    if nested is not None:
        val = getattr(nested, "allow_blob_public_access", None)
        if val is True:
            return True
    public_access = getattr(account, "public_network_access", None)
    if isinstance(public_access, str) and public_access.lower() == "enabled":
        # public_network_access alone is not blob-public; ignore unless allowBlobPublicAccess
        pass
    return False
