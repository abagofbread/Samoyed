from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from samoyed.collectors.assess import assess_file, assess_text
from samoyed.enrichment.report import default_report

# Host paths commonly holding cloud / cluster pivot material. No cloud APIs.
DEFAULT_HOST_PATHS: tuple[str, ...] = (
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.kube/config",
    "~/.config/gcloud/application_default_credentials.json",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
)

ENV_NAME_HINTS: tuple[tuple[str, str], ...] = (
    ("AWS_ACCESS_KEY_ID", "aws_access_key_env"),
    ("AWS_SECRET_ACCESS_KEY", "aws_secret_key_env"),
    ("AWS_SESSION_TOKEN", "aws_session_token_env"),
    ("AZURE_CLIENT_SECRET", "azure_client_secret_env"),
    ("AZURE_CLIENT_ID", "azure_client_secret_env"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "gcp_service_account_json"),
    ("KUBECONFIG", "kubeconfig_file"),
    ("DATABASE_URL", "database_connection_string"),
)


def collect_on_host(
    *,
    target_ref: str | None = None,
    root: Path | None = None,
    extra_paths: list[Path] | None = None,
    resolves_to: Optional[str] = None,
    include_environ: bool = True,
) -> dict[str, Any]:
    """
    Interview the local host for pivot material without cloud API credentials.

    Finds credential-shaped files and environment variables; does not call AWS/GCP/Azure APIs
    or validate keys.
    """
    cwd = (root or Path.cwd()).resolve()
    materials: list[dict[str, Any]] = []
    scanned_files = 0

    paths = [Path(p).expanduser() for p in DEFAULT_HOST_PATHS]
    if extra_paths:
        paths.extend(Path(p).expanduser() for p in extra_paths)

    for path in paths:
        if not path.is_file():
            continue
        scanned_files += 1
        try:
            rel = str(path)
        except ValueError:
            rel = path.name
        for item in assess_file(path, display_path=rel):
            materials.append(_stamp(item, resolves_to=resolves_to, source="on-host-file"))

        # Known kube SA token path without matching assess heuristics
        if path.name == "token" and "serviceaccount" in str(path):
            materials.append(
                _stamp(
                    {
                        "kind": "k8s_service_account_token",
                        "locator": str(path),
                        "confidence": "explicit",
                        "evidence": {"file": str(path), "source": "on-host"},
                    },
                    resolves_to=resolves_to,
                    source="on-host-file",
                )
            )

    if include_environ:
        materials.extend(_environ_materials(resolves_to=resolves_to))

    # Also scan cwd for .env-style files when collecting from a working directory
    for env_path in (cwd / ".env", cwd / ".env.local"):
        if env_path.is_file():
            scanned_files += 1
            for item in assess_file(env_path, display_path=str(env_path)):
                materials.append(_stamp(item, resolves_to=resolves_to, source="on-host-file"))

    materials = _dedupe_materials(materials)
    if not materials:
        materials = [
            {
                "kind": "none_observed",
                "locator": str(cwd),
                "confidence": "explicit",
                "evidence": {
                    "host": os.uname().nodename if hasattr(os, "uname") else "local",
                    "files_scanned": scanned_files,
                    "environ_checked": include_environ,
                },
            }
        ]

    binding: dict[str, Any] = {"materials": materials}
    if target_ref:
        binding["target_ref"] = target_ref
    else:
        binding["target_ref"] = "unbound"
        binding["bind_required"] = True

    report = default_report(
        collector="on-host",
        collector_mode="on-host",
        bindings=[binding],
    )
    report["source_root"] = str(cwd)
    report["files_scanned"] = scanned_files
    report["material_count"] = len(materials)
    report["detected"] = {"mode": "on-host", "signals": ["host-local"]}
    return report


def _environ_materials(*, resolves_to: Optional[str]) -> list[dict[str, Any]]:
    materials: list[dict[str, Any]] = []
    # Named env vars
    for name, kind in ENV_NAME_HINTS:
        value = os.environ.get(name)
        if not value:
            continue
        if name == "GOOGLE_APPLICATION_CREDENTIALS":
            path = Path(value).expanduser()
            if path.is_file():
                for item in assess_file(path, display_path=str(path)):
                    materials.append(_stamp(item, resolves_to=resolves_to, source="on-host-env"))
            materials.append(
                _stamp(
                    {
                        "kind": kind,
                        "locator": f"env:{name}",
                        "confidence": "inferred",
                        "evidence": {"env": name, "path": value},
                    },
                    resolves_to=resolves_to,
                    source="on-host-env",
                )
            )
            continue
        if name == "KUBECONFIG":
            for part in value.split(os.pathsep):
                path = Path(part).expanduser()
                if path.is_file():
                    for item in assess_file(path, display_path=str(path)):
                        materials.append(_stamp(item, resolves_to=resolves_to, source="on-host-env"))
            materials.append(
                _stamp(
                    {
                        "kind": kind,
                        "locator": f"env:{name}",
                        "confidence": "inferred",
                        "evidence": {"env": name},
                    },
                    resolves_to=resolves_to,
                    source="on-host-env",
                )
            )
            continue
        # Avoid putting secret values into the report — name + kind only
        materials.append(
            _stamp(
                {
                    "kind": kind,
                    "locator": f"env:{name}",
                    "confidence": "explicit",
                    "evidence": {"env": name, "set": True},
                },
                resolves_to=resolves_to,
                source="on-host-env",
            )
        )

    # Heuristic scan of a redacted environ dump for AKIA-shaped values
    for key, value in os.environ.items():
        if len(value) > 2000:
            continue
        for item in assess_text(f"{key}={value}", path=f"env:{key}"):
            materials.append(_stamp(item, resolves_to=resolves_to, source="on-host-env"))
    return materials


def _stamp(
    item: dict[str, Any],
    *,
    resolves_to: Optional[str],
    source: str,
) -> dict[str, Any]:
    out = dict(item)
    evidence = dict(out.get("evidence") or {})
    evidence.setdefault("collector_source", source)
    out["evidence"] = evidence
    if resolves_to and out.get("kind") != "none_observed":
        out["resolves_to"] = resolves_to
    return out


def _dedupe_materials(materials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in materials:
        key = (str(item.get("kind")), str(item.get("locator")))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
