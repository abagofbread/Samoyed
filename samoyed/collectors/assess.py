from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key_env", "explicit"),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+"), "aws_secret_key_env", "explicit"),
    (re.compile(r"(?i)aws_session_token\s*[=:]\s*\S+"), "aws_session_token_env", "explicit"),
    (re.compile(r"(?i)azure_client_secret\s*[=:]\s*\S+"), "azure_client_secret_env", "explicit"),
    (re.compile(r"(?i)AZURE_CLIENT_ID\s*[=:]\s*[0-9a-f-]{36}"), "azure_client_secret_env", "inferred"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "generic_credential_file", "explicit"),
    (re.compile(r"DefaultEndpointsProtocol=https;AccountName="), "generic_credential_file", "explicit"),
    (re.compile(r"kind:\s*Config\b"), "kubeconfig_file", "inferred"),
    (re.compile(r"apiVersion:\s*v1\s*\nkind:\s*Secret\b", re.MULTILINE), "k8s_service_account_token", "inferred"),
    (re.compile(r"serviceAccountName:\s*\S+"), "k8s_service_account_token", "inferred"),
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

SCAN_SUFFIXES = frozenset({".env", ".yaml", ".yml", ".json", ".tf", ".toml", ".ini", ".cfg", ".properties"})
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
    }
)

MAX_FILE_BYTES = 256_000


def assess_text(text: str, *, path: str) -> list[dict[str, Any]]:
    materials: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for pattern, kind, confidence in RULES:
        for match in pattern.finditer(text):
            locator = f"{path}:{kind}"
            if kind == "aws_access_key_env":
                locator = f"{path}:{match.group(0)}"
            key = (kind, locator)
            if key in seen:
                continue
            seen.add(key)
            materials.append(
                {
                    "kind": kind,
                    "locator": locator,
                    "confidence": confidence,
                    "evidence": {"file": path, "match": match.group(0)[:80]},
                }
            )
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


def _should_scan_file(path: Path) -> bool:
    name = path.name.lower()
    if name in SCAN_BASENAMES:
        return True
    if name.startswith(".env"):
        return True
    return path.suffix.lower() in SCAN_SUFFIXES
