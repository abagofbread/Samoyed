"""Redact credential fragments before they land in enrichment reports or the graph."""

from __future__ import annotations

import re

_AKIA = re.compile(r"\b(AKIA|ASIA)([A-Z0-9]{12})([A-Z0-9]{4})\b")
_ASSIGNMENT = re.compile(
    r"(?i)\b(aws_secret_access_key|aws_session_token|azure_client_secret|"
    r"aws_access_key_id|client_secret|password|secret|token|api[_-]?key)"
    r"(\s*[=:]\s*)([\"']?)([^\s\"']+)(\3)"
)
_JSON_PASSWORD = re.compile(r'(?i)("password"\s*:\s*")([^"]{4,})(")')
_MYSQL_P = re.compile(r"(?i)(\s-p)([^\s\"']{4,})")
_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_CONN = re.compile(
    r"(?i)\b((?:postgres|mysql|mongodb|redis|amqp|jdbc)://)([^/\s:@]+):([^@\s]+)@"
)
_BEARER = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9\-._~+/]+=*)")


def redact_secret_text(value: str, *, keep: int = 4) -> str:
    """Mask secret-shaped substrings while keeping enough context to locate findings."""
    if not value:
        return value
    text = str(value)

    def _akia(match: re.Match[str]) -> str:
        prefix, mid, suffix = match.group(1), match.group(2), match.group(3)
        return f"{prefix}{'*' * len(mid)}{suffix}"

    def _assign(match: re.Match[str]) -> str:
        name, sep, quote, raw = match.group(1), match.group(2), match.group(3), match.group(4)
        masked = _mask_token(raw, keep=keep)
        return f"{name}{sep}{quote}{masked}{quote}"

    def _json_pw(match: re.Match[str]) -> str:
        return f"{match.group(1)}{_mask_token(match.group(2), keep=keep)}{match.group(3)}"

    def _mysql_p(match: re.Match[str]) -> str:
        return f"{match.group(1)}{_mask_token(match.group(2), keep=keep)}"

    def _conn(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}:{_mask_token(match.group(3), keep=2)}@"

    def _bearer(match: re.Match[str]) -> str:
        return f"{match.group(1)}{_mask_token(match.group(2), keep=keep)}"

    text = _PEM.sub("-----BEGIN PRIVATE KEY-----***-----END PRIVATE KEY-----", text)
    text = _AKIA.sub(_akia, text)
    text = _JSON_PASSWORD.sub(_json_pw, text)
    text = _ASSIGNMENT.sub(_assign, text)
    text = _MYSQL_P.sub(_mysql_p, text)
    text = _CONN.sub(_conn, text)
    text = _BEARER.sub(_bearer, text)
    return text


def redact_evidence(evidence: dict | None) -> dict:
    """Return a copy of evidence with secret-bearing fields masked."""
    if not evidence:
        return {}
    out: dict = {}
    for key, value in evidence.items():
        if key in {"match", "secret", "value", "raw", "snippet", "line"} and isinstance(value, str):
            out[key] = redact_secret_text(value)
        elif isinstance(value, dict):
            out[key] = redact_evidence(value)
        elif isinstance(value, str) and key.lower() in {"path"} and ("credential" in value.lower() or "secret" in value.lower()):
            out[key] = value  # path only
        elif isinstance(value, str) and any(tok in value for tok in ("AKIA", "ASIA", "SECRET", "BEGIN ", "://")):
            out[key] = redact_secret_text(value)
        else:
            out[key] = value
    return out


def _mask_token(token: str, *, keep: int = 4) -> str:
    if len(token) <= keep * 2:
        return "*" * len(token)
    return f"{token[:keep]}{'*' * max(4, len(token) - keep * 2)}{token[-keep:]}"
