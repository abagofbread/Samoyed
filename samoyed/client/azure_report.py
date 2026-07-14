from __future__ import annotations

import re
from typing import Any

from samoyed.cloud.capabilities import map_azure_role
from samoyed.cloud.providers import make_scope_id
from samoyed.credentials.azure import AzureCredential
from samoyed.enumerators.azure.helpers import is_azure_denied

_STORAGE_RE = re.compile(r"/providers/Microsoft\.Storage/storageAccounts/([^/]+)", re.I)
_KEYVAULT_RE = re.compile(r"/providers/Microsoft\.KeyVault/vaults/([^/]+)", re.I)
_WEBAPP_RE = re.compile(r"/providers/Microsoft\.Web/sites/([^/]+)", re.I)


def collect_azure_iam_report(credentials: AzureCredential) -> dict[str, Any]:
    """
    Build a Samoyed iam-report document from live Azure management APIs.

    Intended for client agents running with compromised credentials (SP or user)
    and for `samoyed collect-azure-report` fixture authoring.
    """
    sub = credentials.subscription_id
    scope_id = make_scope_id(credentials.provider, "subscription", sub)
    caller = credentials.get_caller_identity()
    caller_id = caller["native_id"]

    identities: dict[str, dict[str, Any]] = {}
    resources: dict[str, dict[str, Any]] = {}
    grants: list[dict[str, Any]] = []

    _identity(
        identities,
        native_id=caller_id,
        kind=caller["native_kind"],
        display_name=caller.get("display") or caller_id,
        is_caller=True,
        subscription_id=sub,
    )

    _collect_storage(credentials, resources)
    _collect_key_vaults(credentials, resources)
    _collect_role_assignments(credentials, identities, resources, grants)

    return {
        "account_id": sub,
        "provider": "azure",
        "scope_id": scope_id,
        "scope_display": f"Azure subscription {sub[:8]}…",
        "caller_arn": caller_id,
        "source": "samoyed-client",
        "collected_via": "live-azure-api",
        "identities": list(identities.values()),
        "resources": list(resources.values()),
        "grants": grants,
    }


def _collect_storage(credentials: AzureCredential, resources: dict[str, dict[str, Any]]) -> None:
    storage = credentials.client("storage")
    try:
        accounts = list(storage.storage_accounts.list())
    except Exception as exc:
        if is_azure_denied(exc):
            return
        raise
    for account in accounts:
        name = account.name
        native_id = f"StorageAccount:{name}"
        rg = _resource_group_from_id(account.id)
        resources[native_id] = {
            "id": native_id,
            "concept": "DataStore",
            "type": "StorageAccount",
            "name": name,
            "display_name": name,
            "account_name": name,
            "resource_group": rg,
        }


def _collect_key_vaults(credentials: AzureCredential, resources: dict[str, dict[str, Any]]) -> None:
    kv_mgmt = credentials.client("keyvault")
    try:
        vaults = list(kv_mgmt.vaults.list())
    except Exception as exc:
        if is_azure_denied(exc):
            return
        raise

    for vault in vaults:
        vault_name = vault.name
        vault_uri = vault.properties.vault_uri if vault.properties else None
        vault_id = f"KeyVault:{vault_name}"
        resources[vault_id] = {
            "id": vault_id,
            "concept": "SecretStore",
            "type": "KeyVault",
            "name": vault_name,
            "display_name": vault_name,
            "vault_name": vault_name,
            "vault_uri": vault_uri,
            "resource_group": _resource_group_from_id(vault.id),
        }
        if not vault_uri:
            continue
        try:
            from azure.keyvault.secrets import SecretClient
        except ImportError:
            continue
        secret_client = SecretClient(vault_url=vault_uri, credential=credentials.credential())
        try:
            props = list(secret_client.list_properties_of_secrets())
        except Exception as exc:
            if is_azure_denied(exc):
                continue
            raise
        for secret in props:
            sname = secret.name
            if not sname:
                continue
            sid = f"KeyVaultSecret:{vault_name}/{sname}"
            resources[sid] = {
                "id": sid,
                "concept": "SecretStore",
                "type": "KeyVaultSecret",
                "name": sname,
                "display_name": f"{vault_name}/{sname}",
                "secret_name": sname,
                "vault_name": vault_name,
            }


def _collect_role_assignments(
    credentials: AzureCredential,
    identities: dict[str, dict[str, Any]],
    resources: dict[str, dict[str, Any]],
    grants: list[dict[str, Any]],
) -> None:
    auth = credentials.client("authorization")
    role_defs: dict[str, str] = {}

    def role_name(role_definition_id: str) -> str:
        if role_definition_id in role_defs:
            return role_defs[role_definition_id]
        try:
            rd = auth.role_definitions.get_by_id(role_definition_id)
            name = rd.role_name if rd else role_definition_id.split("/")[-1]
        except Exception as exc:
            if is_azure_denied(exc):
                name = role_definition_id.split("/")[-1]
            else:
                raise
        role_defs[role_definition_id] = name
        return name

    try:
        assignments = list(auth.role_assignments.list_for_subscription())
    except Exception as exc:
        if is_azure_denied(exc):
            return
        raise

    for assignment in assignments:
        rname = role_name(assignment.role_definition_id)
        mapping = map_azure_role(rname)
        if not mapping:
            continue
        principal_type = (assignment.principal_type or "Unknown").lower()
        principal_native = f"azure:{principal_type}:{assignment.principal_id}"
        _identity(
            identities,
            native_id=principal_native,
            kind=principal_type.title().replace("serviceprincipal", "ServicePrincipal"),
            display_name=principal_native,
            subscription_id=credentials.subscription_id,
        )
        targets = _targets_for_assignment(assignment.scope, rname, mapping, resources)
        for target_id, rel in targets:
            grants.append(
                {
                    "from": principal_native,
                    "to": target_id,
                    "rel": rel,
                    "role": rname,
                    "scope": assignment.scope,
                    "source": "authorization.roleAssignments.list",
                }
            )


def _targets_for_assignment(
    scope: str,
    role_name: str,
    mapping: Any,
    resources: dict[str, dict[str, Any]],
) -> list[tuple[str, str]]:
    rel = mapping.capability.value
    targets: list[tuple[str, str]] = []

    storage_match = _STORAGE_RE.search(scope or "")
    if storage_match:
        sid = f"StorageAccount:{storage_match.group(1)}"
        if sid in resources:
            targets.append((sid, rel))

    kv_match = _KEYVAULT_RE.search(scope or "")
    if kv_match:
        vault_name = kv_match.group(1)
        kid = f"KeyVault:{vault_name}"
        if kid in resources:
            targets.append((kid, rel))
        if mapping.resource_type == "KeyVaultSecret":
            prefix = f"KeyVaultSecret:{vault_name}/"
            for rid in resources:
                if rid.startswith(prefix):
                    targets.append((rid, rel))

    web_match = _WEBAPP_RE.search(scope or "")
    if web_match:
        wid = f"WebApp:{web_match.group(1)}"
        targets.append((wid, rel))

    if not targets and mapping.resource_type:
        targets.append((f"{mapping.resource_type}:*", rel))
    elif not targets:
        targets.append((scope or "azure:scope:subscription", rel))

    return targets


def _resource_group_from_id(arm_id: str | None) -> str | None:
    if not arm_id:
        return None
    parts = arm_id.split("/")
    try:
        idx = parts.index("resourceGroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None


def _identity(
    identities: dict[str, dict[str, Any]],
    *,
    native_id: str,
    kind: str,
    display_name: str,
    subscription_id: str,
    is_caller: bool = False,
) -> None:
    if native_id in identities:
        return
    entry: dict[str, Any] = {
        "id": native_id,
        "name": display_name,
        "kind": kind,
        "display_name": display_name,
        "provider": "azure",
        "subscription_id": subscription_id,
    }
    if native_id.startswith("azure:serviceprincipal:"):
        entry["client_id"] = native_id.split(":", 2)[-1]
    if is_caller:
        entry["is_caller"] = True
    identities[native_id] = entry
