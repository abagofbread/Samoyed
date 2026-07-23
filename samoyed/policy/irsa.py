"""Parse IAM role trust policies for EKS IRSA (OIDC web identity) bindings.

Graph-inferred only — no live ``sts:AssumeRoleWithWebIdentity`` calls.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

_SA_SUB = re.compile(r"^system:serviceaccount:([^:]+):(.+)$")
_SA_SUB_NS_WILDCARD = re.compile(r"^system:serviceaccount:([^:]+):\*$")
_OIDC_PROVIDER_MARKER = "oidc-provider/"
_WEB_IDENTITY_ACTIONS = frozenset(
    {
        "sts:AssumeRoleWithWebIdentity",
        "sts:*",
        "*",
    }
)


@dataclass(frozen=True)
class IrsaTrustMatch:
    """One SA (or namespace wildcard) allowed to assume ``role_arn`` via OIDC."""

    role_arn: str
    oidc_provider: str
    namespace: str
    sa_name: str | None  # None when sub is system:serviceaccount:ns:*
    audience: str | None = None
    sub_pattern: str = ""
    string_like: bool = False


def is_oidc_provider_arn(principal: str | None) -> bool:
    text = str(principal or "")
    return _OIDC_PROVIDER_MARKER in text or text.startswith("Federated:") and _OIDC_PROVIDER_MARKER in text


def normalize_oidc_provider(principal: str) -> str:
    """Strip a ``Federated:`` prefix if present; return the OIDC provider ARN/value."""
    raw = str(principal or "").strip()
    if raw.startswith("Federated:"):
        raw = raw[len("Federated:") :]
    return raw


def parse_irsa_trust_document(
    trust: Any,
    *,
    role_arn: str,
) -> list[IrsaTrustMatch]:
    """Extract IRSA SA matches from an AssumeRolePolicyDocument (or one statement)."""
    doc = _coerce_trust(trust)
    if not doc:
        return []
    matches: list[IrsaTrustMatch] = []
    for stmt in _statements(doc):
        matches.extend(parse_irsa_trust_statement(stmt, role_arn=role_arn))
    return matches


def parse_irsa_trust_statement(
    stmt: dict[str, Any],
    *,
    role_arn: str,
) -> list[IrsaTrustMatch]:
    if not isinstance(stmt, dict):
        return []
    if str(stmt.get("Effect") or "Allow") != "Allow":
        return []
    if not _allows_web_identity(stmt.get("Action")):
        return []

    providers = _federated_principals(stmt.get("Principal"))
    if not providers:
        return []

    subs, aud, string_like = _condition_subs_and_aud(stmt.get("Condition"))
    if not subs:
        return []

    out: list[IrsaTrustMatch] = []
    for provider in providers:
        for sub in subs:
            ns_wild = _SA_SUB_NS_WILDCARD.match(sub)
            if ns_wild:
                out.append(
                    IrsaTrustMatch(
                        role_arn=role_arn,
                        oidc_provider=provider,
                        namespace=ns_wild.group(1),
                        sa_name=None,
                        audience=aud,
                        sub_pattern=sub,
                        string_like=True,
                    )
                )
                continue
            exact = _SA_SUB.match(sub)
            if exact:
                out.append(
                    IrsaTrustMatch(
                        role_arn=role_arn,
                        oidc_provider=provider,
                        namespace=exact.group(1),
                        sa_name=exact.group(2),
                        audience=aud,
                        sub_pattern=sub,
                        string_like=string_like,
                    )
                )
    return out


def sa_refs_for_match(
    match: IrsaTrustMatch,
    *,
    inventored_sas: Iterable[tuple[str, str]] | None = None,
) -> list[tuple[str, str]]:
    """Return ``(namespace, sa_name)`` pairs for a trust match.

    Namespace wildcards expand to inventored SAs in that namespace when provided.
    """
    if match.sa_name is not None:
        return [(match.namespace, match.sa_name)]
    inventored = list(inventored_sas or [])
    return [(ns, name) for ns, name in inventored if ns == match.namespace]


def _coerce_trust(trust: Any) -> dict[str, Any] | None:
    if trust is None:
        return None
    if isinstance(trust, str):
        try:
            trust = json.loads(trust)
        except (json.JSONDecodeError, TypeError):
            return None
    if isinstance(trust, dict):
        # Single statement passed as trust_doc
        if "Effect" in trust or "Principal" in trust:
            return {"Statement": [trust]}
        return trust
    return None


def _statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement", [])
    if isinstance(stmt, dict):
        return [stmt]
    if isinstance(stmt, list):
        return [s for s in stmt if isinstance(s, dict)]
    return []


def _allows_web_identity(action: Any) -> bool:
    if action is None:
        # Trust statements often omit Action (implies STS assume for the principal type).
        return True
    actions: list[str]
    if isinstance(action, str):
        actions = [action]
    elif isinstance(action, list):
        actions = [str(a) for a in action]
    else:
        return False
    for act in actions:
        if act in _WEB_IDENTITY_ACTIONS:
            return True
        if act.endswith(":AssumeRoleWithWebIdentity"):
            return True
        if act.endswith(":*") and act.lower().startswith("sts"):
            return True
    return False


def _federated_principals(principal: Any) -> list[str]:
    if principal is None:
        return []
    if isinstance(principal, str):
        return [normalize_oidc_provider(principal)] if is_oidc_provider_arn(principal) else []
    if not isinstance(principal, dict):
        return []
    out: list[str] = []
    fed = principal.get("Federated")
    values: list[Any]
    if isinstance(fed, list):
        values = fed
    elif fed is not None:
        values = [fed]
    else:
        values = []
    for val in values:
        text = str(val)
        if is_oidc_provider_arn(text):
            out.append(normalize_oidc_provider(text))
    return out


def _condition_subs_and_aud(
    condition: Any,
) -> tuple[list[str], str | None, bool]:
    """Return (sub patterns, audience, used_string_like)."""
    if not isinstance(condition, dict):
        return [], None, False
    subs: list[str] = []
    aud: str | None = None
    used_like = False

    for op in ("StringEquals", "StringLike", "ForAnyValue:StringEquals", "ForAnyValue:StringLike"):
        block = condition.get(op)
        if not isinstance(block, dict):
            continue
        is_like = "Like" in op
        for key, val in block.items():
            key_l = str(key).lower()
            values = val if isinstance(val, list) else [val]
            if key_l.endswith(":sub") or key_l == "sub":
                for item in values:
                    text = str(item)
                    if text.startswith("system:serviceaccount:"):
                        subs.append(text)
                        used_like = used_like or is_like
            if key_l.endswith(":aud") or key_l == "aud":
                for item in values:
                    aud = str(item)
                    break
    # Dedupe subs preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for s in subs:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq, aud, used_like
