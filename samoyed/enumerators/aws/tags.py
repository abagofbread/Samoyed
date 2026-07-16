"""Normalize AWS/K8s tag maps and infer environment labels."""

from __future__ import annotations

from typing import Any

ENV_TAG_KEYS = (
    "environment",
    "Environment",
    "env",
    "Env",
    "stage",
    "Stage",
    "deployment",
    "Deployment",
    "samoyed:environment",
)

_ENV_ALIASES = {
    "production": "prod",
    "prod": "prod",
    "prd": "prod",
    "live": "prod",
    "staging": "staging",
    "stage": "staging",
    "stg": "staging",
    "development": "dev",
    "dev": "dev",
    "develop": "dev",
    "test": "test",
    "testing": "test",
    "qa": "qa",
    "uat": "uat",
    "sandbox": "sandbox",
}


def normalize_tag_map(tags: Any) -> dict[str, str]:
    """Accept AWS list[{Key,Value}] / list[{key,value}] / dict → flat dict."""
    out: dict[str, str] = {}
    if not tags:
        return out
    if isinstance(tags, dict):
        for k, v in tags.items():
            if k is not None and v is not None:
                out[str(k)] = str(v)
        return out
    if isinstance(tags, list):
        for entry in tags:
            if not isinstance(entry, dict):
                continue
            key = entry.get("Key") or entry.get("key")
            val = entry.get("Value") or entry.get("value")
            if key is not None and val is not None:
                out[str(key)] = str(val)
    return out


def environment_from_tags(tags: dict[str, str] | None) -> str | None:
    if not tags:
        return None
    for key in ENV_TAG_KEYS:
        if key in tags and tags[key].strip():
            return canonicalize_environment(tags[key])
    lower = {k.lower(): v for k, v in tags.items()}
    for key in ("environment", "env", "stage"):
        if key in lower and lower[key].strip():
            return canonicalize_environment(lower[key])
    return None


def canonicalize_environment(raw: str) -> str:
    token = raw.strip().lower()
    return _ENV_ALIASES.get(token, token)


def environment_from_props(props: dict[str, Any]) -> str | None:
    """Prefer explicit environment prop, then tags."""
    env = props.get("environment")
    if isinstance(env, str) and env.strip():
        return canonicalize_environment(env)
    tags = props.get("tags")
    if isinstance(tags, dict):
        return environment_from_tags(tags)
    return None
