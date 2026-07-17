from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

CollectMode = Literal["static", "on-host"]


@dataclass(frozen=True)
class DetectedSurface:
    """What `samoyed collect` inferred about a target."""

    mode: CollectMode
    root: Path
    signals: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    suggested_adapters: tuple[str, ...] = field(default_factory=tuple)


def detect_collect_target(
    target: str | Path,
    *,
    mode: CollectMode | None = None,
) -> DetectedSurface:
    """
    Infer collector mode from a path or host token.

    - ``host``, ``host:local``, ``local``, or ``.`` with mode on-host → on-host interview
    - Existing path → static / repo scan (signals drive adapter selection)
    """
    raw = str(target).strip()
    if mode == "on-host" or _is_host_token(raw):
        root = Path.cwd() if _is_host_token(raw) else Path(raw).expanduser()
        return DetectedSurface(
            mode="on-host",
            root=root if root.exists() else Path.cwd(),
            signals=("host-local",),
            notes=("No cloud API credentials used; host filesystem/env only.",),
            suggested_adapters=("on-host",),
        )

    path = Path(raw).expanduser()
    if not path.exists():
        raise FileNotFoundError(raw)

    root = path.resolve()
    if mode == "static" or mode is None:
        signals = detect_repo_signals(root)
        adapters = _adapters_for_signals(signals)
        return DetectedSurface(
            mode="static",
            root=root,
            signals=signals,
            suggested_adapters=adapters,
        )

    raise ValueError(f"Unsupported collect mode: {mode}")


def detect_repo_signals(root: Path) -> tuple[str, ...]:
    """Lightweight path heuristics — not a full IaC parser."""
    found: list[str] = []
    scan_root = root if root.is_dir() else root.parent
    names = {p.name for p in _iter_shallow_files(scan_root)}
    suffixes = {p.suffix.lower() for p in _iter_shallow_files(scan_root)}

    if ".tf" in suffixes or "terraform.tfstate" in names or "main.tf" in names:
        found.append("terraform")
    if {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"} & names or ".dockerfile" in suffixes:
        found.append("docker")
    if "Chart.yaml" in names or _has_k8s_manifest(scan_root):
        found.append("kubernetes")
    if any(n.startswith(".env") for n in names):
        found.append("dotenv")
    if {"serverless.yml", "serverless.yaml", "template.yaml", "template.yml"} & names:
        found.append("serverless")
    if (scan_root / ".aws" / "credentials").exists() or "credentials" in names:
        found.append("aws-credentials-file")
    found.append("config-files")
    return tuple(dict.fromkeys(found))


def _iter_shallow_files(root: Path, *, max_files: int = 2000) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", ".terraform", "node_modules", "venv", ".venv"} for part in path.parts):
            continue
        files.append(path)
        if len(files) >= max_files:
            break
    return files


def _adapters_for_signals(signals: tuple[str, ...]) -> tuple[str, ...]:
    adapters: list[str] = ["builtin-rules"]
    # External tool reports are opt-in via --ingest; we only *suggest* names here.
    if "terraform" in signals:
        adapters.append("tool-report")
    if "kubernetes" in signals or "docker" in signals or "dotenv" in signals:
        adapters.append("tool-report")
    return tuple(dict.fromkeys(adapters))


def _is_host_token(raw: str) -> bool:
    lowered = raw.lower()
    return lowered in {"host", "host:local", "local", "localhost", "on-host"}


def _has_k8s_manifest(root: Path) -> bool:
    markers = ("kind:", "apiVersion:")
    for path in _iter_shallow_files(root):
        if path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        if _file_looks_k8s(path, markers):
            return True
    return False


def _file_looks_k8s(path: Path, markers: tuple[str, ...]) -> bool:
    try:
        if path.stat().st_size > 256_000:
            return False
        text = path.read_text(encoding="utf-8", errors="ignore")[:4000]
    except OSError:
        return False
    return all(m in text for m in markers)
