"""Human-readable labels for collector pivot materials.

Graph labels must answer: what was found, where, and what it unlocks —
never kind slugs like ``generic_credential_file`` or catalog titles like
``Credential file``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from samoyed.enrichment.redact import redact_secret_text

_KIND_SLUG = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
_LEGACY_CATALOG = re.compile(
    r"(?i)^(Credential file|AWS access key \(environment\)|AWS secret key \(environment\)|"
    r"AWS session token \(environment\)|Database connection string|Kubeconfig file|"
    r"Kubernetes service account token|GCP service account key \(JSON\)|"
    r"Azure client secret \(environment\))\s*:"
)
_MATERIAL_NATIVE = re.compile(r"^material:[a-z0-9_]+:[a-f0-9]+$")
_SECRETISH_HINT = re.compile(r"(?i)cred|secret|password|passwd|token|vault")
_DBISH_HINT = re.compile(
    r"(?i)(?:^|[-_])(?:db|rds|mysql|postgres|aurora|database)(?:$|[-_])|goat-db|-db$"
)
_INFRA_HINT = re.compile(r"(?i)role|cluster|bucket|service|task|deploy|instance-profile|lab-cluster")
_AKIA = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z*]{8,})\b")
_ENV_ASSIGN = re.compile(
    r"(?i)\b([A-Z][A-Z0-9_]{2,})\s*[=:]\s*[\"']?[^\s\"']+"
)
_JSON_NAME = re.compile(r'(?i)"name"\s*:\s*"([A-Z][A-Z0-9_]{2,})"')
_PASSWORD_ASSIGN = re.compile(r"(?i)\bpassword\b")


def classify_finding(kind: str, match_snippet: str | None = None) -> str:
    """Narrow a material kind into a short finding title (never a kind slug)."""
    snippet = (match_snippet or "").strip()
    low = snippet.lower()

    if kind == "aws_access_key_env":
        key = _AKIA.search(snippet)
        if key:
            return f"AWS access key { _short_secret(key.group(1)) }"
        return "AWS access key"
    if kind == "aws_secret_key_env":
        return "AWS secret access key"
    if kind == "aws_session_token_env":
        return "AWS session token"
    if kind == "azure_client_secret_env":
        env = _first_env_name(snippet)
        return f"Azure client secret ({env})" if env else "Azure client secret"
    if kind == "gcp_service_account_json":
        return "GCP service account key"
    if kind == "kubeconfig_file":
        return "Kubeconfig"
    if kind == "k8s_service_account_token":
        return "Kubernetes SA token"
    if kind == "api_key":
        env = _first_env_name(snippet)
        return f"API key ({env})" if env else "Third-party API key"
    if kind == "oauth_token":
        return "OAuth token"
    if kind == "email_credential":
        return "Email account credentials"
    if kind == "k8s_client_cert":
        return "Kubernetes client certificate"
    if kind == "database_connection_string":
        env = _first_env_name(snippet) or _json_name(snippet)
        if "mysql" in low or "-p" in low:
            return "MySQL password"
        if env:
            return f"Database endpoint env {env}"
        if any(tok in low for tok in ("rds_endpoint", "database_url", "db_host", "db_endpoint")):
            return "Database endpoint"
        return "Database connection string"
    if kind == "generic_credential_file":
        if "begin" in low and "private key" in low:
            return "Private key"
        if "secretsmanager" in low or "aws_secretsmanager_secret" in low:
            return "Secrets Manager secret reference"
        if "defaultendpointsprotocol" in low or "accountname=" in low:
            return "Azure storage connection string"
        if _PASSWORD_ASSIGN.search(snippet):
            return "Hardcoded password"
        env = _first_env_name(snippet)
        if env and any(tok in env.lower() for tok in ("pass", "secret", "token", "key", "cred")):
            return f"Hardcoded {env}"
        return "Hardcoded credential"
    if kind == "none_observed":
        return "No credentials observed"
    # Unknown kinds: humanize snake_case, never echo raw slug alone without spaces.
    return kind.replace("_", " ").strip() or "Credential material"


def format_source_path(path: str | None, *, max_parts: int = 2) -> str:
    if not path:
        return ""
    cleaned = str(path).strip().replace("\\", "/")
    if cleaned.startswith("env:"):
        return cleaned
    name = Path(cleaned).name
    parts = [p for p in Path(cleaned).parts if p not in {".", "/"}]
    if len(parts) >= 2 and max_parts >= 2:
        return "/".join(parts[-max_parts:])
    return name or cleaned


def pick_name_hint(
    hints: list[str] | None,
    *,
    kind: str = "",
    finding: str = "",
    match: str | None = None,
) -> str | None:
    """Choose the unlock target for a label — DB instance for passwords, not secret names."""
    cleaned = [str(h).strip() for h in (hints or []) if h and str(h).strip()]
    if not cleaned:
        return None

    finding_l = (finding or "").lower()
    match_l = (match or "").lower()
    prefer_db = (
        kind in {"generic_credential_file", "database_connection_string"}
        or any(tok in finding_l or tok in match_l for tok in ("password", "mysql", "database", "rds", "dsn"))
    )
    prefer_role = kind.startswith("aws_") or "access key" in finding_l or "iam" in finding_l

    scored: list[tuple[int, int, str]] = []
    for idx, hint in enumerate(cleaned):
        score = 0
        if prefer_db and _DBISH_HINT.search(hint):
            score += 20
        if prefer_db and _SECRETISH_HINT.search(hint):
            # Secret names like RDS_CREDS are not the impact target.
            score -= 15
        if not prefer_db and _SECRETISH_HINT.search(hint):
            score += 12
        if prefer_role and re.search(r"(?i)role|user|sa\b|service.account", hint):
            score += 10
        if _INFRA_HINT.search(hint) and prefer_db:
            score -= 10
        if prefer_db and re.search(r"(?i)bucket|cluster|service_worker|tf_files", hint):
            score -= 12
        scored.append((score, -idx, hint))

    scored.sort(reverse=True)
    best_score, _, best = scored[0]
    if best_score < 0:
        return None
    return best


def material_summary(
    *,
    kind: str,
    locator: str | None = None,
    evidence: dict[str, Any] | None = None,
    name_hints: list[str] | None = None,
    include_location: bool = True,
) -> str:
    """One-line graph/detail label: what (+ where) (+ unlock hint).

    When materials collapse across files, set ``include_location=False`` and put
    observation sites on HAS_MATERIAL edges instead of the node title.
    """
    evidence = evidence or {}
    match = evidence.get("match")
    finding = evidence.get("finding") or classify_finding(kind, str(match) if match else None)
    if is_weak_label(str(finding), kind=kind):
        finding = classify_finding(kind, str(match) if match else None)

    parts = [finding]
    if include_location:
        file_path = evidence.get("file") or _file_from_locator(locator, kind)
        line = evidence.get("line")
        where = format_source_path(str(file_path) if file_path else None)
        if where and line is not None and str(line).isdigit():
            where = f"{where}:{line}"
        elif not where and locator:
            where = _human_locator(str(locator), kind)
        if where:
            parts.append(f"in {where}")

    hint = pick_name_hint(
        name_hints if name_hints is not None else evidence.get("name_hints"),
        kind=kind,
        finding=finding,
        match=str(match) if match else None,
    )
    if hint:
        parts.append(f"→ {hint}")
    elif kind == "k8s_service_account_token":
        ns = evidence.get("k8s_namespace")
        sa = evidence.get("k8s_service_account")
        if ns and sa:
            parts.append(f"→ {ns}/{sa}")

    return " ".join(parts)


def material_detail_props(
    *,
    kind: str,
    locator: str,
    evidence: dict[str, Any] | None = None,
    name_hints: list[str] | None = None,
    include_location: bool = True,
) -> dict[str, Any]:
    """Extra node props so the UI/detail pane has real context."""
    evidence = dict(evidence or {})
    match = evidence.get("match")
    finding = classify_finding(kind, str(match) if match else None)
    # Prefer a non-weak stamped finding only when it adds specificity.
    stamped = evidence.get("finding")
    if stamped and not is_weak_label(str(stamped), kind=kind):
        finding = str(stamped)
    evidence["finding"] = finding

    file_path = evidence.get("file") or _file_from_locator(locator, kind)
    line = evidence.get("line")
    summary = material_summary(
        kind=kind,
        locator=locator,
        evidence=evidence,
        name_hints=name_hints,
        include_location=include_location,
    )
    preview = None
    if match:
        preview = redact_secret_text(str(match))[:120]

    props: dict[str, Any] = {
        "finding": finding,
        "summary": summary,
        "display_name": summary,
        "name": summary,
    }
    if file_path:
        props["source_file"] = str(file_path)
        props["source_basename"] = Path(str(file_path)).name
    if line is not None:
        props["source_line"] = line
    if preview:
        props["match_preview"] = preview
    if name_hints:
        props["name_hints"] = list(name_hints)
    return props


def enrich_assess_item(item: dict[str, Any]) -> dict[str, Any]:
    """Stamp finding/summary onto a collector material dict."""
    kind = str(item.get("kind") or "")
    evidence = dict(item.get("evidence") or {})
    match = evidence.get("match")
    finding = classify_finding(kind, str(match) if match else None)
    evidence["finding"] = finding
    item["evidence"] = evidence
    item["finding"] = finding
    item["summary"] = material_summary(
        kind=kind,
        locator=str(item.get("locator") or ""),
        evidence=evidence,
        name_hints=item.get("name_hints"),
    )
    return item


def is_weak_label(text: str | None, *, kind: str | None = None) -> bool:
    """True when a stored label is catalog junk / kind slug / legacy format."""
    if not text or not str(text).strip():
        return True
    raw = str(text).strip()
    low = raw.lower()
    if _MATERIAL_NATIVE.match(raw):
        return True
    if _LEGACY_CATALOG.match(raw):
        return True
    if low in {
        "credential file",
        "credential material",
        "generic credential file",
        "generic_credential_file",
        "database connection string",
        "unclassified credential material on disk (rule-detected).",
    }:
        return True
    if "generic_credential_file" in low or raw.startswith("Credential file"):
        return True
    if kind and (low == kind.lower() or low == kind.replace("_", " ").lower()):
        return True
    if _KIND_SLUG.match(raw):
        return True
    # Legacy "Catalog title: locator" (locator often embeds kind slug)
    if ": " in raw and any(
        tok in raw
        for tok in (
            "(environment):",
            "Credential file:",
            ":generic_credential_file",
            ":aws_secret_key_env",
            ":aws_access_key_env",
            ":database_connection_string",
        )
    ):
        return True
    return False


def relabel_material_node(props: dict[str, Any]) -> dict[str, Any]:
    """Recompute human labels on an existing PivotMaterial node props dict."""
    kind = str(props.get("material_kind") or "")
    if not kind and props.get("native_kind") != "PivotMaterial":
        return props
    if not kind:
        native = str(props.get("native_id") or "")
        if native.startswith("material:"):
            parts = native.split(":")
            kind = parts[1] if len(parts) >= 2 else ""
    if not kind:
        return props

    evidence = props.get("evidence") if isinstance(props.get("evidence"), dict) else {}
    locator = str(props.get("locator") or "")
    hints = props.get("name_hints") if isinstance(props.get("name_hints"), list) else None
    label_props = material_detail_props(
        kind=kind,
        locator=locator,
        evidence=evidence,
        name_hints=hints,
    )
    props.update(label_props)
    return props


def relabel_pivot_materials(graph: Any) -> int:
    """Fix weak PivotMaterial labels in-place. Returns count updated."""
    updated = 0
    nodes = getattr(graph, "nodes", None)
    if not isinstance(nodes, dict):
        return 0
    for node in nodes.values():
        props = getattr(node, "props", None)
        if not isinstance(props, dict):
            continue
        if props.get("native_kind") != "PivotMaterial" and not props.get("material_kind"):
            continue
        before = str(props.get("display_name") or props.get("summary") or "")
        relabel_material_node(props)
        after = str(props.get("display_name") or "")
        if after and after != before:
            updated += 1
        elif is_weak_label(before, kind=str(props.get("material_kind") or "")):
            updated += 1
    return updated


def _short_secret(value: str) -> str:
    raw = str(value)
    if len(raw) <= 12:
        return raw
    return f"{raw[:4]}…{raw[-4:]}"


def _first_env_name(snippet: str) -> str | None:
    m = _ENV_ASSIGN.search(snippet or "")
    if m:
        return m.group(1)
    return _json_name(snippet)


def _json_name(snippet: str) -> str | None:
    m = _JSON_NAME.search(snippet or "")
    return m.group(1) if m else None


def _human_locator(locator: str, kind: str) -> str:
    """Strip trailing kind slugs from legacy locators like path:line:kind."""
    raw = locator.strip()
    if raw.startswith("env:"):
        return raw
    parts = raw.split(":")
    if len(parts) >= 3 and parts[-1] == kind and parts[-2].isdigit():
        path = ":".join(parts[:-2])
        return f"{format_source_path(path)}:{parts[-2]}"
    if len(parts) >= 2 and parts[-1] == kind:
        return format_source_path(":".join(parts[:-1]))
    if len(parts) >= 2 and parts[-1].endswith("_env"):
        return format_source_path(parts[0])
    return format_source_path(raw)


def _file_from_locator(locator: str | None, kind: str) -> str | None:
    if not locator:
        return None
    raw = str(locator)
    if raw.startswith("env:"):
        return raw
    parts = raw.split(":")
    if len(parts) >= 3 and parts[-1] == kind and parts[-2].isdigit():
        return ":".join(parts[:-2])
    if len(parts) >= 2 and parts[-1] == kind:
        return ":".join(parts[:-1])
    if len(parts) >= 2 and parts[-1].endswith("_env"):
        return parts[0]
    if len(parts) >= 2 and parts[-1].isdigit():
        return ":".join(parts[:-1])
    if len(parts) >= 2:
        return parts[0]
    return raw
