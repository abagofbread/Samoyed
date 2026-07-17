"""AWS Organizations Service Control Policy (SCP) helpers.

SCPs are an account-level *ceiling* (and explicit Deny) on every principal in a
member account — similar to permissions boundaries, but shared across the account
and layered (account + parent OUs + root). Management accounts are exempt.

We store effective SCP allow-sets / denies on the account ``ScopeBoundary`` node
and clamp in ``collect_principal_actions`` — no new edge types.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class ScpDocument:
    """One SCP policy document (Allow + Deny action patterns)."""

    policy_id: str
    name: str
    allow_actions: frozenset[str] = field(default_factory=frozenset)
    deny_actions: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_full_aws_access(self) -> bool:
        return bool(self.allow_actions & {"*", "*:*"}) and not self.deny_actions


@dataclass(frozen=True)
class ScpConstraints:
    """Account-effective SCP ceiling for clamping identity actions."""

    allow_sets: tuple[frozenset[str], ...] = ()
    deny_actions: frozenset[str] = field(default_factory=frozenset)
    exempt: bool = False
    policy_ids: tuple[str, ...] = ()
    policy_names: tuple[str, ...] = ()

    @property
    def applies(self) -> bool:
        return not self.exempt and (bool(self.allow_sets) or bool(self.deny_actions))


def parse_scp_document(
    doc: Any,
    *,
    policy_id: str = "",
    name: str = "",
) -> ScpDocument:
    """Parse an SCP JSON document into allow/deny action patterns (Resource ignored)."""
    if isinstance(doc, str):
        doc = json.loads(doc)
    if not isinstance(doc, dict):
        return ScpDocument(policy_id=policy_id, name=name)

    allows: list[str] = []
    denies: list[str] = []
    for stmt in _statements(doc):
        effect = str(stmt.get("Effect") or "").lower()
        raw = stmt.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        # NotAction is rare in SCPs; treat as unbounded for that effect (skip precise expand).
        if stmt.get("NotAction") and not raw:
            if effect == "allow":
                allows.append("*")
            elif effect == "deny":
                denies.append("*")
            continue
        for action in raw:
            if not action:
                continue
            text = str(action)
            if effect == "allow":
                allows.append(text)
            elif effect == "deny":
                denies.append(text)
    return ScpDocument(
        policy_id=policy_id,
        name=name,
        allow_actions=frozenset(allows),
        deny_actions=frozenset(denies),
    )


def merge_scp_documents(docs: Iterable[ScpDocument]) -> ScpConstraints:
    """Combine SCPs attached along the account→OU→root path."""
    docs = [d for d in docs if d.allow_actions or d.deny_actions or d.policy_id]
    if not docs:
        return ScpConstraints()
    allow_sets = tuple(d.allow_actions for d in docs if d.allow_actions)
    # Empty Allow with only Deny still applies (deny-only SCP).
    deny: set[str] = set()
    for d in docs:
        deny |= set(d.deny_actions)
    return ScpConstraints(
        allow_sets=allow_sets,
        deny_actions=frozenset(deny),
        policy_ids=tuple(d.policy_id for d in docs if d.policy_id),
        policy_names=tuple(d.name for d in docs if d.name),
    )


def scp_props_for_scope(constraints: ScpConstraints) -> dict[str, Any]:
    """Props to merge onto the account ScopeBoundary node."""
    if constraints.exempt:
        return {
            "scp_exempt": True,
            "scp_allow_sets": [],
            "scp_deny_actions": [],
            "scp_policy_ids": list(constraints.policy_ids),
            "scp_policy_names": list(constraints.policy_names),
        }
    if not constraints.applies and not constraints.policy_ids:
        return {}
    return {
        "scp_exempt": False,
        "scp_allow_sets": [sorted(s) for s in constraints.allow_sets],
        "scp_deny_actions": sorted(constraints.deny_actions),
        "scp_policy_ids": list(constraints.policy_ids),
        "scp_policy_names": list(constraints.policy_names),
    }


def constraints_from_scope_props(props: dict[str, Any] | None) -> ScpConstraints | None:
    """Rebuild constraints from ScopeBoundary props (or None if absent)."""
    if not props:
        return None
    if props.get("scp_exempt"):
        return ScpConstraints(exempt=True)
    allow_sets_raw = props.get("scp_allow_sets")
    flat = props.get("scp_allow_actions")
    denies = frozenset(str(a) for a in (props.get("scp_deny_actions") or []))
    policy_ids = tuple(str(x) for x in (props.get("scp_policy_ids") or []))
    policy_names = tuple(str(x) for x in (props.get("scp_policy_names") or []))

    allow_sets: list[frozenset[str]] = []
    if isinstance(allow_sets_raw, list) and allow_sets_raw:
        for entry in allow_sets_raw:
            if isinstance(entry, (list, tuple, set, frozenset)):
                allow_sets.append(frozenset(str(a) for a in entry))
    elif flat is not None:
        allow_sets.append(frozenset(str(a) for a in flat))

    if not allow_sets and not denies and not policy_ids:
        return None
    return ScpConstraints(
        allow_sets=tuple(allow_sets),
        deny_actions=denies,
        policy_ids=policy_ids,
        policy_names=policy_names,
    )


def apply_scp_clamp(
    identity_actions: set[str],
    constraints: ScpConstraints | None,
    *,
    action_matches,
    apply_allow_ceiling,
) -> set[str]:
    """identity ∩ every SCP Allow − SCP Denies (action patterns only)."""
    if not constraints or constraints.exempt or not constraints.applies:
        return identity_actions

    out = set(identity_actions)
    for allow_set in constraints.allow_sets:
        out = apply_allow_ceiling(out, set(allow_set))

    if constraints.deny_actions:
        out = {a for a in out if _action_survives_deny(a, constraints.deny_actions, action_matches)}
    return out


def _action_survives_deny(action: str, denies: frozenset[str], action_matches) -> bool:
    for deny in denies:
        # Deny covers this action (iam:* denies iam:CreateUser; iam:CreateUser denies itself).
        if action_matches(deny, action):
            return False
        # Conservative: drop service:* / broad grants that a more specific Deny carves into.
        if "*" in action and action not in {"*", "*:*"} and action_matches(action, deny):
            return False
    return True


def _statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement", [])
    if isinstance(stmt, dict):
        return [stmt]
    return list(stmt)
