"""BloodHound / AzureHound / SharpHound kind → Samoyed relationship mapping.

Samoyed never uses AZ* strings as graph ``rel_type`` values — only as BH source kinds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# BH edge kinds we intentionally drop (containment / unknown noise).
IGNORED_EDGE_KINDS: frozenset[str] = frozenset(
    {
        "AZContains",
        "Contains",
        "AZHasRole",  # role assignment scaffolding; prefer concrete grant edges
    }
)

# SharpHound ACE RightName → BH-style edge kind (then remapped below).
ACE_RIGHT_TO_KIND: dict[str, str] = {
    "genericall": "GenericAll",
    "genericwrite": "GenericWrite",
    "writedacl": "WriteDacl",
    "writeowner": "WriteOwner",
    "forcechangepassword": "ForceChangePassword",
    "allextendedrights": "GenericAll",
    "getchanges": "GetChanges",
    "getchangesall": "GetChangesAll",
    "addkeycredentiallink": "GenericWrite",
}


@dataclass(frozen=True)
class MappedEdge:
    """One or more Samoyed edges produced from a single BH edge."""

    rel_type: str
    props: dict[str, Any]
    # When set, reverse BH start/end for the Samoyed edge.
    reverse: bool = False
    # Optional override for destination concept (e.g. SecretStore for KV).
    target_concept: str | None = None


def normalize_bh_kind(kind: str | None) -> str:
    if not kind:
        return ""
    text = str(kind).strip()
    # OpenGraph / CE sometimes use lowercase or spaced forms.
    aliases = {
        "memberof": "MemberOf",
        "azmemberof": "AZMemberOf",
        "hassession": "HasSession",
        "adminto": "AdminTo",
        "canrdp": "CanRDP",
        "canpsremote": "CanPSRemote",
        "dcsync": "DCSync",
        "syncedtoaduser": "SyncedToADUser",
    }
    return aliases.get(text.lower(), text)


def map_bh_edge(
    kind: str,
    *,
    src_kinds: list[str] | None = None,
    dst_kinds: list[str] | None = None,
) -> list[MappedEdge] | None:
    """Return Samoyed edge specs for a BH kind, or None to ignore."""
    k = normalize_bh_kind(kind)
    if not k or k in IGNORED_EDGE_KINDS:
        return None

    src_kinds = src_kinds or []
    dst_kinds = dst_kinds or []

    if k in {"AZMemberOf", "MemberOf"}:
        directory = "entra" if _is_azure_kind(src_kinds + dst_kinds) else "ad"
        return [MappedEdge("MEMBER_OF", {"directory": directory, "bh_kind": k})]

    if k in {"AZAddSecret", "AZMGAddSecret"}:
        return [
            MappedEdge(
                "CAN_ASSUME_ROLE",
                {"mechanism": "add-secret", "bh_kind": k},
            )
        ]

    if k == "AZOwns" and _targets_app_or_sp(dst_kinds):
        return [MappedEdge("CAN_ASSUME_ROLE", {"mechanism": "owns", "bh_kind": k})]

    if k in {"AZManagedIdentity", "AZRunsAs"}:
        return [MappedEdge("EXECUTES_AS", {"bh_kind": k})]

    if k == "AZGetSecrets":
        return [
            MappedEdge(
                "READS",
                {"bh_kind": k, "resource_type": "KeyVault"},
                target_concept="SecretStore",
            )
        ]

    if k in {"AZContributor", "AZOwner", "AZUserAccessAdministrator"}:
        return [MappedEdge("CONTROLS", {"bh_kind": k, "azure_rbac": k})]

    if k in {"AZMGGrantRole", "AZGlobalAdmin", "AZPrivilegedRoleAdmin"}:
        return [
            MappedEdge(
                "CAN_PRIVESC_TO",
                {"mechanism": _admin_mechanism(k), "bh_kind": k},
            )
        ]

    if k == "AZExecuteCommand":
        return [MappedEdge("CAN_ESCAPE_TO", {"mechanism": "run-command", "bh_kind": k})]

    if k in {"AdminTo", "CanRDP", "CanPSRemote"}:
        return [MappedEdge("CONTROLS", {"bh_kind": k, "host_access": k})]

    if k == "HasSession":
        return [
            MappedEdge(
                "CAN_STEAL_CREDS_FROM",
                {
                    "bh_kind": k,
                    "mechanism": "lsass-mimikatz",
                    "action": "host:interactive-session",
                    "session_type": "interactive",
                    "harvest_method": "interactive-token-theft",
                },
            ),
        ]

    if k == "SyncedToADUser":
        # BH: Entra → AD. Attack pivot we model: AD user → Entra user.
        return [
            MappedEdge(
                "CAN_ASSUME_ROLE",
                {"mechanism": "synced-identity", "bh_kind": k},
                reverse=True,
            )
        ]

    if k in {"ForceChangePassword", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"}:
        if _is_user_or_group(dst_kinds) or not dst_kinds:
            rel = "CAN_PRIVESC_TO" if k == "ForceChangePassword" else "CONTROLS"
            return [MappedEdge(rel, {"mechanism": k.lower(), "bh_kind": k})]
        return [MappedEdge("CONTROLS", {"mechanism": k.lower(), "bh_kind": k})]

    if k in {"DCSync", "GetChangesAll"}:
        return [MappedEdge("CAN_PRIVESC_TO", {"mechanism": "dcsync", "bh_kind": k})]

    if k == "GetChanges":
        # Alone insufficient; importer pairs with GetChangesAll.
        return [MappedEdge("CONTROLS", {"mechanism": "getchanges", "bh_kind": k})]

    # Unknown kinds: ignore (sparse mapping).
    return None


def _admin_mechanism(kind: str) -> str:
    return {
        "AZMGGrantRole": "mg-grant-role",
        "AZGlobalAdmin": "global-admin",
        "AZPrivilegedRoleAdmin": "privileged-role-admin",
    }.get(kind, kind.lower())


def _is_azure_kind(kinds: list[str]) -> bool:
    return any(str(k).upper().startswith("AZ") for k in kinds)


def _targets_app_or_sp(kinds: list[str]) -> bool:
    joined = " ".join(kinds).lower()
    return any(tok in joined for tok in ("serviceprincipal", "application", "app", "azapp"))


def _is_user_or_group(kinds: list[str]) -> bool:
    joined = " ".join(kinds).lower()
    return any(tok in joined for tok in ("user", "group"))


def node_directory(kinds: list[str], props: dict[str, Any] | None = None) -> str:
    props = props or {}
    if props.get("directory") in {"entra", "ad"}:
        return str(props["directory"])
    if _is_azure_kind(kinds) or props.get("tenant-id") or props.get("tenantid"):
        return "entra"
    return "ad"


def native_id_for_node(
    object_id: str,
    kinds: list[str],
    props: dict[str, Any] | None = None,
) -> str:
    """Stable Samoyed native_id for a BloodHound node."""
    props = props or {}
    oid = str(object_id or props.get("objectid") or props.get("objectId") or "").strip()
    name = str(props.get("name") or props.get("displayname") or props.get("displayName") or oid)
    kinds_l = [str(k).lower() for k in kinds]
    directory = node_directory(kinds, props)

    if any("keyvaultsecret" in k for k in kinds_l):
        return f"azure:keyvaultsecret:{oid or name}"
    if any("keyvault" in k for k in kinds_l):
        return f"azure:keyvault:{oid or name}"
    if any("managedidentity" in k for k in kinds_l):
        return f"azure:managedidentity:{oid}"
    if any(k in {"azserviceprincipal", "serviceprincipal"} or "serviceprincipal" in k for k in kinds_l):
        app_id = props.get("appid") or props.get("appId") or props.get("applicationid") or oid
        return f"azure:serviceprincipal:{app_id}"
    if any(k in {"azapp", "azapplication", "application"} or k.endswith("application") for k in kinds_l):
        app_id = props.get("appid") or props.get("appId") or oid
        return f"azure:application:{app_id}"
    if any("azrole" in k or k == "role" for k in kinds_l) and directory == "entra":
        return f"azure:role:{oid or name}"
    if any("tenant" in k for k in kinds_l):
        return f"azure:tenant:{oid}"

    if directory == "entra" or any(k.startswith("az") for k in kinds_l):
        if any("group" in k for k in kinds_l):
            return f"azure:group:{oid}"
        if any("user" in k for k in kinds_l):
            return f"azure:user:{oid}"
        if any(tok in " ".join(kinds_l) for tok in ("vm", "device", "computer")):
            return f"azure:vm:{oid or name}"
        return f"azure:object:{oid or name}"

    # On-prem AD
    sid_or_name = oid or name
    if any("computer" in k for k in kinds_l):
        return f"ad:computer:{sid_or_name}"
    if any("group" in k for k in kinds_l):
        return f"ad:group:{sid_or_name}"
    if any("user" in k for k in kinds_l):
        return f"ad:user:{sid_or_name}"
    if any("domain" in k for k in kinds_l):
        return f"ad:domain:{sid_or_name}"
    return f"ad:object:{sid_or_name}"


def concept_for_node(kinds: list[str], props: dict[str, Any] | None = None) -> str:
    """Return ConceptType value string."""
    props = props or {}
    kinds_l = [str(k).lower() for k in kinds]
    if any("keyvault" in k for k in kinds_l):
        return "SecretStore"
    if any("computer" in k or k in {"azvm", "azdevice"} or "vm" in k for k in kinds_l):
        return "Workload"
    if any("tenant" in k or "domain" in k for k in kinds_l):
        return "ScopeBoundary"
    return "Identity"


def primary_kind(kinds: list[str]) -> str:
    for k in kinds:
        if k and k not in {"Base", "Entity", "AZBase"}:
            return k
    return kinds[0] if kinds else "Unknown"
