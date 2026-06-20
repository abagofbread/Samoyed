from __future__ import annotations

import subprocess
from pathlib import Path

from samoyed.firing_range.config import COMPOSE_FILE


def compose_file() -> Path:
    if not COMPOSE_FILE.is_file():
        raise FileNotFoundError(f"Firing range compose file not found: {COMPOSE_FILE}")
    return COMPOSE_FILE


def run_compose(*args: str) -> None:
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file()), *args],
        check=True,
    )


def compose_up(*, detach: bool = True) -> None:
    args = ["up"]
    if detach:
        args.append("-d")
    run_compose(*args)


def compose_down() -> None:
    run_compose("down")
