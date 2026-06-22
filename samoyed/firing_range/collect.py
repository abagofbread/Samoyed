from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from samoyed.client.iam_report import collect_iam_report
from samoyed.credentials.aws import AwsCredential
from samoyed.firing_range import aws_helpers
from samoyed.firing_range.aws_authz_export import export_account_authorization_details
from samoyed.firing_range.config import (
    ACCOUNT_INVENTORY_FILE,
    ARTIFACT_SNAPSHOTS_DIR,
    ARTIFACTS_DIR,
    AWS_AUTHZ_FILE,
    CLIENT_IAM_REPORT_FILE,
    CREDENTIALS_FILE,
    DEFAULT_ACCESS_KEY,
    DEFAULT_ENDPOINT,
    DEFAULT_REGION,
    DEFAULT_SECRET_KEY,
    LATEST_SNAPSHOT_DIR,
    PROBE_REPORT_FILE,
    SEED_METADATA_FILE,
)
from samoyed.firing_range.seed import load_leaked_credentials, seed_aws_lab
from samoyed.probes.runner import run_api_probes

ARTIFACT_FILENAMES = {
    "seed_metadata": "seed-metadata.json",
    "credentials": "leaked-user-credentials.json",
    "client_iam_report": "client-iam-report.json",
    "aws_authz_details": "aws-authz-details.json",
    "probe_report": "probe-report.json",
    "account_inventory": "account-inventory.json",
    "manifest": "manifest.json",
}


def collect_firing_range_artifacts(
    *,
    endpoint_url: str = DEFAULT_ENDPOINT,
    region: str = DEFAULT_REGION,
    output_dir: Path | None = None,
    reseed: bool = False,
    write_canonical: bool = True,
    update_latest: bool = True,
) -> dict[str, Any]:
    """
    Collect firing-range outputs into a timestamped snapshot under `.samoyed/firing-range/`.

    Mimics what you'd get from a real cloud assessment: client recon report, IAM authz
    export, probe results, and a coarse account inventory. All paths stay gitignored.
    """
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACT_SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    collected_at = datetime.now(timezone.utc)
    stamp = collected_at.strftime("%Y%m%d-%H%M%S")
    snapshot_dir = output_dir or (ARTIFACT_SNAPSHOTS_DIR / stamp)
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    seed_meta = seed_aws_lab(endpoint_url=endpoint_url, region=region) if reseed else _load_seed_metadata()
    leaked = load_leaked_credentials()
    cred = AwsCredential(
        access_key=leaked["AccessKeyId"],
        secret_key=leaked["SecretAccessKey"],
        region=region,
        endpoint_url=leaked.get("endpoint_url") or endpoint_url,
    )

    client_report = collect_iam_report(cred)
    authz = export_account_authorization_details(
        endpoint_url=endpoint_url,
        region=region,
        access_key=DEFAULT_ACCESS_KEY,
        secret_key=DEFAULT_SECRET_KEY,
    )
    probe_report = run_api_probes(cred)
    inventory = collect_account_inventory(endpoint_url=endpoint_url, region=region)

    payloads: dict[str, Any] = {
        "seed_metadata": seed_meta,
        "credentials": leaked,
        "client_iam_report": client_report,
        "aws_authz_details": authz,
        "probe_report": probe_report.to_dict(),
        "account_inventory": inventory,
    }

    written: dict[str, str] = {}
    for key, filename in ARTIFACT_FILENAMES.items():
        if key == "manifest":
            continue
        path = snapshot_dir / filename
        path.write_text(json.dumps(payloads[key], indent=2, default=str), encoding="utf-8")
        written[key] = str(path)

    manifest = {
        "collected_at": collected_at.isoformat(),
        "endpoint": endpoint_url,
        "region": region,
        "snapshot_dir": str(snapshot_dir),
        "files": written,
        "summary": {
            "account_id": client_report.get("account_id"),
            "caller_arn": client_report.get("caller_arn"),
            "iam_report_identities": len(client_report.get("identities", [])),
            "iam_report_resources": len(client_report.get("resources", [])),
            "iam_report_grants": len(client_report.get("grants", [])),
            "authz_users": len(authz.get("UserDetailList", [])),
            "authz_roles": len(authz.get("RoleDetailList", [])),
            "probe_allowed": len(probe_report.allowed),
            "probe_denied": len(probe_report.denied),
            "inventory_buckets": len(inventory.get("s3_buckets", [])),
            "inventory_secrets": len(inventory.get("secrets", [])),
            "inventory_lambdas": len(inventory.get("lambda_functions", [])),
            "clutter_bronze_buckets": len((seed_meta.get("clutter") or {}).get("bronze", {}).get("buckets", [])),
            "clutter_silver_pipelines": (seed_meta.get("clutter") or {}).get("silver", {}).get("pipelines", []),
        },
    }
    manifest_path = snapshot_dir / ARTIFACT_FILENAMES["manifest"]
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    written["manifest"] = str(manifest_path)

    if write_canonical:
        _write_canonical(payloads)

    if update_latest:
        _refresh_latest_snapshot(snapshot_dir)

    manifest["files"] = written
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def collect_account_inventory(*, endpoint_url: str, region: str) -> dict[str, Any]:
    """Admin-style asset listing — best effort per service."""
    inventory: dict[str, Any] = {
        "source": "samoyed-firing-range-inventory",
        "endpoint": endpoint_url,
        "region": region,
        "collected_via": "live-aws-api",
    }

    s3 = aws_helpers.aws_client("s3", endpoint_url=endpoint_url, region=region)
    secrets = aws_helpers.aws_client("secretsmanager", endpoint_url=endpoint_url, region=region)
    lam = aws_helpers.aws_client("lambda", endpoint_url=endpoint_url, region=region)

    inventory["s3_buckets"] = _list_s3_buckets(s3)
    inventory["secrets"] = _list_secrets(secrets)
    inventory["lambda_functions"] = _list_lambda_functions(lam)
    inventory["eks_clusters"] = _list_named(
        aws_helpers.aws_client("eks", endpoint_url=endpoint_url, region=region),
        "list_clusters",
        "clusters",
    )
    inventory["ec2_instances"] = _list_ec2_instances(
        aws_helpers.aws_client("ec2", endpoint_url=endpoint_url, region=region)
    )
    inventory["load_balancers"] = _list_named(
        aws_helpers.aws_client("elbv2", endpoint_url=endpoint_url, region=region),
        "describe_load_balancers",
        "LoadBalancers",
        name_key="LoadBalancerName",
    )
    inventory["codepipelines"] = _list_named(
        aws_helpers.aws_client("codepipeline", endpoint_url=endpoint_url, region=region),
        "list_pipelines",
        "pipelines",
        name_key="name",
    )
    inventory["codebuild_projects"] = _list_named(
        aws_helpers.aws_client("codebuild", endpoint_url=endpoint_url, region=region),
        "list_projects",
        "projects",
    )
    return inventory


def _load_seed_metadata() -> dict[str, Any]:
    if SEED_METADATA_FILE.is_file():
        return json.loads(SEED_METADATA_FILE.read_text(encoding="utf-8"))
    return {"note": "seed-metadata.json missing; run samoyed firing-range seed"}


def _write_canonical(payloads: dict[str, Any]) -> None:
    mappings = {
        SEED_METADATA_FILE: payloads["seed_metadata"],
        CREDENTIALS_FILE: payloads["credentials"],
        CLIENT_IAM_REPORT_FILE: payloads["client_iam_report"],
        AWS_AUTHZ_FILE: payloads["aws_authz_details"],
        PROBE_REPORT_FILE: payloads["probe_report"],
        ACCOUNT_INVENTORY_FILE: payloads["account_inventory"],
    }
    for path, data in mappings.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _refresh_latest_snapshot(snapshot_dir: Path) -> None:
    if LATEST_SNAPSHOT_DIR.exists():
        shutil.rmtree(LATEST_SNAPSHOT_DIR)
    shutil.copytree(snapshot_dir, LATEST_SNAPSHOT_DIR)


def _list_s3_buckets(s3: Any) -> list[dict[str, str]]:
    try:
        resp = s3.list_buckets()
    except ClientError:
        return []
    return [{"name": b["Name"]} for b in resp.get("Buckets", [])]


def _list_secrets(secrets: Any) -> list[dict[str, str]]:
    try:
        resp = secrets.list_secrets()
    except ClientError:
        return []
    return [{"name": s.get("Name", ""), "arn": s.get("ARN", "")} for s in resp.get("SecretList", [])]


def _list_lambda_functions(lam: Any) -> list[dict[str, str]]:
    try:
        resp = lam.list_functions()
    except ClientError:
        return []
    return [
        {"name": f.get("FunctionName", ""), "arn": f.get("FunctionArn", "")}
        for f in resp.get("Functions", [])
    ]


def _list_ec2_instances(ec2: Any) -> list[dict[str, Any]]:
    try:
        resp = ec2.describe_instances()
    except ClientError:
        return []
    items: list[dict[str, Any]] = []
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            name = next(
                (t["Value"] for t in inst.get("Tags", []) if t.get("Key") == "Name"),
                inst.get("InstanceId", ""),
            )
            items.append({"instance_id": inst.get("InstanceId", ""), "name": name, "state": inst.get("State", {}).get("Name", "")})
    return items


def _list_named(
    client: Any,
    method: str,
    response_key: str,
    *,
    name_key: str = "name",
) -> list[dict[str, str]]:
    try:
        resp = getattr(client, method)()
    except (ClientError, AttributeError):
        return []
    raw = resp.get(response_key, [])
    if raw and isinstance(raw[0], str):
        return [{"name": item} for item in raw]
    return [{"name": item.get(name_key, str(item))} for item in raw]
