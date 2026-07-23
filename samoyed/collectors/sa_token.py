"""Correlate Kubernetes service account tokens to typed impact targets.

Decodes JWT payloads locally (no signature verify) — no live STS calls.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

_SA_SUB = re.compile(r"^system:serviceaccount:([^:]+):(.+)$")
_JWT_LIKE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Base64url-decode a JWT payload without verifying the signature."""
    raw = (token or "").strip().strip("\"'")
    if not raw or raw.count(".") < 2:
        return None
    if not _JWT_LIKE.match(raw.split()[0] if raw.split() else raw):
        # Allow whitespace-trimmed tokens that still look like JWT
        parts = raw.split(".")
        if len(parts) < 3:
            return None
    parts = raw.split(".")
    payload_b64 = parts[1]
    pad = "=" * (-len(payload_b64) % 4)
    try:
        data = base64.urlsafe_b64decode(payload_b64 + pad)
        parsed = json.loads(data.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def sa_ref_from_jwt_payload(payload: dict[str, Any]) -> tuple[str, str] | None:
    sub = str(payload.get("sub") or "")
    match = _SA_SUB.match(sub)
    if not match:
        return None
    return match.group(1), match.group(2)


def sa_ref_from_token_path(path: str | Path) -> tuple[str, str] | None:
    """Infer namespace (and optionally SA) from a projected serviceaccount token path."""
    p = Path(path)
    # .../namespaces/<ns>/serviceaccounts/<sa>/... or .../serviceaccount/token
    parts = list(p.parts)
    if "namespaces" in parts:
        i = parts.index("namespaces")
        if i + 3 < len(parts) and parts[i + 2] == "serviceaccounts":
            return parts[i + 1], parts[i + 3]
    # Sibling namespace file next to token
    if p.name == "token" and "serviceaccount" in str(p):
        ns_file = p.parent / "namespace"
        if ns_file.is_file():
            try:
                ns = ns_file.read_text(encoding="utf-8").strip()
            except OSError:
                ns = ""
            if ns:
                # SA name unknown without JWT — leave sa as namespace default hint via empty?
                # Prefer reading sa name from path segment when present.
                return ns, "default"
        # downward API /var/run/secrets/kubernetes.io/serviceaccount/token — SA unknown
        return None
    return None


def enrich_sa_token_material(material: dict[str, Any]) -> dict[str, Any]:
    """Add ``impact_targets`` / evidence for a k8s_service_account_token material."""
    if str(material.get("kind") or "") != "k8s_service_account_token":
        return material
    out = dict(material)
    evidence = dict(out.get("evidence") or {})
    targets = [t for t in (out.get("impact_targets") or []) if isinstance(t, dict)]
    name_hints = [str(h) for h in (out.get("name_hints") or []) if h]

    ns: str | None = None
    sa: str | None = None

    # Prefer JWT in evidence.match / secret / locator blob
    token_text = ""
    for key in ("match", "secret", "token", "value"):
        val = evidence.get(key)
        if isinstance(val, str) and val.count(".") >= 2:
            token_text = val
            break
    if not token_text:
        loc = str(out.get("locator") or "")
        # locator may be path only — try reading file when it looks like a token path
        if loc.endswith("/token") or loc.endswith(":token"):
            path = loc.split(":")[0]
            try:
                token_text = Path(path).read_text(encoding="utf-8").strip()
            except OSError:
                token_text = ""

    if token_text:
        payload = decode_jwt_payload(token_text)
        if payload:
            evidence["jwt_iss"] = payload.get("iss")
            evidence["jwt_sub"] = payload.get("sub")
            ref = sa_ref_from_jwt_payload(payload)
            if ref:
                ns, sa = ref

    if not (ns and sa):
        path_hint = str(evidence.get("file") or out.get("locator") or "")
        path_ref = sa_ref_from_token_path(path_hint.split(":")[0])
        if path_ref and path_ref[1] != "default":
            ns, sa = path_ref
        elif path_ref and not ns:
            ns = path_ref[0]
            # Keep SA unknown — don't invent "default" SA name for projected volume path
            sa = None

    if ns and sa:
        target_name = f"{ns}:{sa}"
        if not any(
            str(t.get("kind")) == "k8s_service_account" and str(t.get("name")) == target_name
            for t in targets
        ):
            targets.append({"kind": "k8s_service_account", "name": target_name})
        if target_name not in name_hints:
            name_hints.append(target_name)
        evidence["k8s_namespace"] = ns
        evidence["k8s_service_account"] = sa

    out["evidence"] = evidence
    if targets:
        out["impact_targets"] = targets
    if name_hints:
        out["name_hints"] = name_hints
    return out
