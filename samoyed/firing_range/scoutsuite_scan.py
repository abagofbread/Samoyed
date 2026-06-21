from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


class ScoutSuiteNotInstalledError(RuntimeError):
    pass


class ScoutSuiteScanError(RuntimeError):
    pass


def scoutsuite_available() -> bool:
    return shutil.which("scout") is not None


def run_scoutsuite_scan(
    *,
    endpoint_url: str,
    region: str,
    access_key: str,
    secret_key: str,
    report_dir: Path,
    services: str = "iam,s3,lambda",
    timeout: int = 600,
    use_docker: bool = False,
    docker_image: str = "binbash/sec-scoutsuite:5.4.0",
) -> dict[str, Any]:
    """
    Run the real ScoutSuite CLI against an AWS-compatible endpoint.

    For LocalStack, prefer `aws-authz-details` export — ScoutSuite does not natively
    route STS calls through custom endpoints without a proxy (see Aerides project).
    """
    report_dir = report_dir.resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    if use_docker or not scoutsuite_available():
        return _run_scoutsuite_docker(
            endpoint_url=endpoint_url,
            region=region,
            access_key=access_key,
            secret_key=secret_key,
            report_dir=report_dir,
            services=services,
            timeout=timeout,
            docker_image=docker_image,
        )

    return _run_scoutsuite_cli(
        endpoint_url=endpoint_url,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        report_dir=report_dir,
        services=services,
        timeout=timeout,
    )


def _run_scoutsuite_cli(
    *,
    endpoint_url: str,
    region: str,
    access_key: str,
    secret_key: str,
    report_dir: Path,
    services: str,
    timeout: int,
) -> dict[str, Any]:
    if not scoutsuite_available():
        raise ScoutSuiteNotInstalledError(
            "ScoutSuite CLI not found. Install with: pip install scoutsuite, or pass --docker"
        )

    env = os.environ.copy()
    env["AWS_ENDPOINT_URL"] = endpoint_url
    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    env["AWS_DEFAULT_REGION"] = region
    env.setdefault("AWS_EC2_METADATA_DISABLED", "true")

    cmd = [
        "scout",
        "aws",
        "--no-browser",
        "--report-dir",
        str(report_dir),
        "--services",
        services,
        "--force",
    ]
    proc = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise ScoutSuiteScanError(
            f"ScoutSuite exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    result_file = _find_results_file(report_dir)
    if not result_file:
        raise ScoutSuiteScanError(f"No scoutsuite_results*.js under {report_dir}")
    return {
        "tool": "scoutsuite",
        "mode": "cli",
        "report_dir": str(report_dir),
        "result_file": str(result_file),
        "services": services,
        "endpoint": endpoint_url,
    }


def _run_scoutsuite_docker(
    *,
    endpoint_url: str,
    region: str,
    access_key: str,
    secret_key: str,
    report_dir: Path,
    services: str,
    timeout: int,
    docker_image: str,
) -> dict[str, Any]:
    if not shutil.which("docker"):
        raise ScoutSuiteScanError("Docker not available for ScoutSuite fallback")

    host_endpoint = endpoint_url
    if "localhost" in endpoint_url:
        host_endpoint = endpoint_url.replace("localhost", "host.docker.internal")

    cmd = [
        "docker",
        "run",
        "--rm",
        "-e",
        f"AWS_ENDPOINT_URL={host_endpoint}",
        "-e",
        f"AWS_ACCESS_KEY_ID={access_key}",
        "-e",
        f"AWS_SECRET_ACCESS_KEY={secret_key}",
        "-e",
        f"AWS_DEFAULT_REGION={region}",
        "-v",
        f"{report_dir}:/report",
        docker_image,
        "aws",
        "--no-browser",
        "--force",
        "--report-dir",
        "/report",
        "--services",
        services.replace(",", " "),
        "--regions",
        region,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScoutSuiteScanError(f"ScoutSuite docker timed out after {timeout}s") from exc

    if proc.returncode != 0:
        raise ScoutSuiteScanError(
            "ScoutSuite docker failed (LocalStack often needs a proxy — use aws-authz-details instead)\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    result_file = _find_results_file(report_dir)
    if not result_file:
        raise ScoutSuiteScanError(f"No scoutsuite_results*.js under {report_dir}")
    return {
        "tool": "scoutsuite",
        "mode": "docker",
        "report_dir": str(report_dir),
        "result_file": str(result_file),
        "services": services,
        "endpoint": host_endpoint,
    }


def _find_results_file(report_dir: Path) -> Path | None:
    patterns = [
        report_dir.glob("**/scoutsuite_results*.js"),
        report_dir.glob("scoutsuite-results/scoutsuite_results*.js"),
    ]
    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend(pattern)
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)
