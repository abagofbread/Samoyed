"""ARM scope → Samoyed native_id resolution for Azure role assignments."""

from __future__ import annotations

import re
from typing import Any, Iterable

_STORAGE_RE = re.compile(r"/providers/Microsoft\.Storage/storageAccounts/([^/]+)", re.I)
_KEYVAULT_RE = re.compile(r"/providers/Microsoft\.KeyVault/vaults/([^/]+)", re.I)
_WEBAPP_RE = re.compile(r"/providers/Microsoft\.Web/sites/([^/]+)", re.I)
_VM_RE = re.compile(r"/providers/Microsoft\.Compute/virtualMachines/([^/]+)", re.I)
_AUTOMATION_RE = re.compile(
    r"/providers/Microsoft\.Automation/automationAccounts/([^/]+)", re.I
)


def targets_for_assignment(
    scope: str | None,
    mapping: Any,
    inventored: Iterable[str] | None = None,
) -> list[tuple[str, str]]:
    """Resolve (target_native_id, rel_type) pairs for an Azure role assignment scope.

    Prefers inventored resource native_ids when provided; falls back to concrete
    IDs parsed from the ARM scope; only wildcards when nothing matches.
    """
    rel = mapping.capability.value
    inventored_set = set(inventored or [])
    candidates: list[str] = []

    storage_match = _STORAGE_RE.search(scope or "")
    if storage_match:
        candidates.append(f"StorageAccount:{storage_match.group(1)}")

    kv_match = _KEYVAULT_RE.search(scope or "")
    if kv_match:
        vault_name = kv_match.group(1)
        candidates.append(f"KeyVault:{vault_name}")
        if getattr(mapping, "resource_type", None) == "KeyVaultSecret":
            prefix = f"KeyVaultSecret:{vault_name}/"
            for rid in inventored_set:
                if rid.startswith(prefix):
                    candidates.append(rid)

    web_match = _WEBAPP_RE.search(scope or "")
    if web_match:
        name = web_match.group(1)
        # Prefer FunctionApp if inventored under that name; else WebApp.
        fn_id = f"FunctionApp:{name}"
        web_id = f"WebApp:{name}"
        if fn_id in inventored_set:
            candidates.append(fn_id)
        else:
            candidates.append(web_id)

    vm_match = _VM_RE.search(scope or "")
    if vm_match:
        candidates.append(f"AzureVM:{vm_match.group(1)}")

    auto_match = _AUTOMATION_RE.search(scope or "")
    if auto_match:
        candidates.append(f"AutomationAccount:{auto_match.group(1)}")

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    candidates = unique

    if inventored_set and candidates:
        preferred = [c for c in candidates if c in inventored_set]
        # KeyVaultSecret expansions already inventored-only; keep vault itself if preferred empty
        if preferred:
            return [(c, rel) for c in preferred]

    if candidates:
        return [(c, rel) for c in candidates]

    if getattr(mapping, "resource_type", None):
        return [(f"{mapping.resource_type}:*", rel)]
    return [(scope or "azure:scope:subscription", rel)]


def resource_group_from_id(arm_id: str | None) -> str | None:
    if not arm_id:
        return None
    parts = arm_id.split("/")
    try:
        idx = parts.index("resourceGroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None
