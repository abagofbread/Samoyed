from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from samoyed.collectors.correlate import correlate_materials, extract_terraform_names
from samoyed.enrichment.labels import enrich_assess_item
from samoyed.enrichment.redact import redact_evidence, redact_secret_text

# (pattern, material_kind, confidence, secret_group_index|None)
# secret_group_index: capture group with the raw secret for fingerprinting (1-based), or 0 for full match
RULES: tuple[tuple[re.Pattern[str], str, str, int | None], ...] = (
    (re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "aws_access_key_env", "explicit", 1),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([^\s\"']+)"), "aws_secret_key_env", "explicit", 1),
    (re.compile(r"(?i)aws_session_token\s*[=:]\s*[\"']?([^\s\"']+)"), "aws_session_token_env", "explicit", 1),
    (re.compile(r"(?i)azure_client_secret\s*[=:]\s*[\"']?([^\s\"']+)"), "azure_client_secret_env", "explicit", 1),
    (re.compile(r"(?i)AZURE_CLIENT_ID\s*[=:]\s*([0-9a-f-]{36})"), "azure_client_secret_env", "inferred", 1),
    (
        re.compile(r"""(?i)\bpassword\s*=\s*["']([^"'\n]{4,})["']"""),
        "generic_credential_file",
        "explicit",
        1,
    ),
    (
        re.compile(r'(?i)"password"\s*:\s*"([^"]{4,})"'),
        "generic_credential_file",
        "explicit",
        1,
    ),
    (
        re.compile(r"(?i)mysql\b[^\n]*\s-p([^\s\"']{4,})"),
        "database_connection_string",
        "explicit",
        1,
    ),
    (
        re.compile(
            r"(?i)\b(?:RDS_ENDPOINT|DATABASE_URL|DB_HOST|DB_ENDPOINT)\b\s*[=:]\s*[\"']?([^\s\"']+)"
        ),
        "database_connection_string",
        "inferred",
        None,
    ),
    (
        re.compile(r'(?i)"name"\s*:\s*"(RDS_ENDPOINT|DATABASE_URL|DB_HOST)"'),
        "database_connection_string",
        "inferred",
        None,
    ),
    (
        re.compile(r"(?i)aws_secretsmanager_secret\b|[\"']arn:aws:secretsmanager:"),
        "generic_credential_file",
        "inferred",
        None,
    ),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "generic_credential_file", "explicit", None),
    (re.compile(r"DefaultEndpointsProtocol=https;AccountName="), "generic_credential_file", "explicit", None),
    (re.compile(r"kind:\s*Config\b"), "kubeconfig_file", "inferred", None),
    (re.compile(r"apiVersion:\s*v1\s*\nkind:\s*Secret\b", re.MULTILINE), "k8s_service_account_token", "inferred", None),
    (re.compile(r"serviceAccountName:\s*\S+"), "k8s_service_account_token", "inferred", None),
)

SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        ".terraform",
        "vendor",
    }
)

SCAN_SUFFIXES = frozenset(
    {
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".tf",
        ".toml",
        ".ini",
        ".cfg",
        ".properties",
        ".sh",
        ".tpl",
        ".php",
        ".inc",
        ".sql",
        ".conf",
    }
)
SCAN_BASENAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "docker-compose.yml",
        "docker-compose.yaml",
        "serverless.yml",
        "serverless.yaml",
        "task_definition.json",
        "credentials",
    }
)

MAX_FILE_BYTES = 256_000


def assess_text(text: str, *, path: str) -> list[dict[str, Any]]:
    materials: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for pattern, kind, confidence, secret_group in RULES:
        for match in pattern.finditer(text):
            snippet = match.group(0)[:160]
            line = text.count("\n", 0, match.start()) + 1
            if kind == "aws_access_key_env":
                locator = f"{path}:{redact_secret_text(match.group(0))}"
            elif kind in {"generic_credential_file", "database_connection_string"}:
                # path:line — kind lives on the material, not the locator slug
                locator = f"{path}:{line}"
            else:
                locator = f"{path}:{kind}"
            key = (kind, locator)
            if key in seen:
                continue
            seen.add(key)
            item: dict[str, Any] = {
                "kind": kind,
                "locator": locator,
                "confidence": confidence,
                "evidence": redact_evidence({"file": path, "match": snippet, "line": line}),
            }
            if secret_group is not None:
                try:
                    secret = match.group(secret_group)
                except IndexError:
                    secret = None
                if secret:
                    item["_secret_value"] = secret
            materials.append(enrich_assess_item(item))
    return materials


def assess_file(path: Path, *, display_path: Optional[str] = None) -> list[dict[str, Any]]:
    if path.stat().st_size > MAX_FILE_BYTES:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    rel = display_path or str(path)
    return assess_text(text, path=rel)


def iter_static_files(root: Path) -> list[Path]:
    files: list[Path] = []
    if root.is_file():
        return [root] if _should_scan_file(root) else []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if _should_scan_file(path):
            files.append(path)
    return files


def assess_tree(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]], int]:
    """Scan a tree: materials (with transient secrets), TF declared names, file count."""
    root = root.resolve()
    path_root = root if root.is_dir() else root.parent
    materials: list[dict[str, Any]] = []
    declared: list[dict[str, str]] = []
    scanned = 0
    for path in iter_static_files(root):
        scanned += 1
        try:
            rel = str(path.relative_to(path_root))
        except ValueError:
            rel = path.name
        materials.extend(assess_file(path, display_path=rel))
        if path.suffix.lower() == ".tf":
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            declared.extend(extract_terraform_names(text, source_path=rel))
    materials = correlate_materials(materials, declared_resources=declared)
    materials = [enrich_assess_item(m) for m in materials]
    return materials, declared, scanned


def _should_scan_file(path: Path) -> bool:
    name = path.name.lower()
    if name in SCAN_BASENAMES:
        return True
    if name.startswith(".env"):
        return True
    return path.suffix.lower() in SCAN_SUFFIXES
