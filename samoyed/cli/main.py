from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import typer
import uvicorn

from samoyed.credentials.loader import (
    load_aws_credential,
    load_azure_credential,
    load_gcp_credential,
    load_k8s_credential,
)
from samoyed.probes.runner import get_probe_catalog, run_api_probes
from samoyed.extensions.discovery import init_extension
from samoyed.firing_range import (
    ARTIFACTS_DIR,
    CLIENT_IAM_REPORT_FILE,
    CREDENTIALS_FILE,
    DEFAULT_ENDPOINT,
    DEFAULT_REGION,
    SCOUTSUITE_DIR,
    ScoutSuiteNotInstalledError,
    ScoutSuiteScanError,
    compose_down,
    compose_up,
    load_leaked_credentials,
    ping_emulator,
    run_scoutsuite_scan,
    scoutsuite_available,
    seed_aws_lab,
)
from samoyed.sessions import SESSION_STORE
from samoyed.cloud.concepts import CloudProvider

app = typer.Typer(no_args_is_help=True, help="Samoyed — BloodHound for cloud")
firing_range_app = typer.Typer(help="Emulated vulnerable clouds (LocalStack, no lab data in repo)")
sessions_app = typer.Typer(help="Manage attack-graph sessions")
collect_app = typer.Typer(help="Static collectors that produce enrichment reports")
app.add_typer(firing_range_app, name="firing-range")
app.add_typer(sessions_app, name="sessions")
app.add_typer(collect_app, name="collect")


@firing_range_app.command("status")
def firing_range_status_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
) -> None:
    """Check whether the emulated AWS endpoint is reachable."""
    typer.echo(
        json.dumps(
            {
                "endpoint": endpoint_url,
                "region": region,
                "reachable": ping_emulator(endpoint_url=endpoint_url, region=region),
            },
            indent=2,
        )
    )


@firing_range_app.command("up")
def firing_range_up_cmd() -> None:
    """Start LocalStack via docker compose (firing-range/docker-compose.yml)."""
    try:
        compose_up()
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    except Exception as exc:
        typer.echo(f"docker compose failed: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo("LocalStack starting on http://localhost:4566")
    typer.echo("Run: samoyed firing-range seed")


@firing_range_app.command("down")
def firing_range_down_cmd() -> None:
    """Stop LocalStack."""
    try:
        compose_down()
    except Exception as exc:
        typer.echo(f"docker compose failed: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo("LocalStack stopped")


@firing_range_app.command("seed")
def firing_range_seed_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
) -> None:
    """Seed vulnerable IAM/S3/Secrets topology into the emulator via API."""
    if not ping_emulator(endpoint_url=endpoint_url, region=region):
        typer.echo(f"Emulator not reachable at {endpoint_url}. Run: samoyed firing-range up", err=True)
        raise typer.Exit(1)
    try:
        meta = seed_aws_lab(endpoint_url=endpoint_url, region=region)
    except Exception as exc:
        typer.echo(f"Seed failed: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps(meta, indent=2))
    typer.echo("Run: samoyed firing-range enum")


@firing_range_app.command("client-report")
def firing_range_client_report_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
    credentials_file: Path = typer.Option(CREDENTIALS_FILE, help="Leaked user key JSON"),
    output: Path = typer.Option(CLIENT_IAM_REPORT_FILE, help="Where to write iam-report JSON"),
) -> None:
    """Collect iam-report JSON from live APIs using leaked-user credentials (client agent simulation)."""
    from samoyed.client.iam_report import collect_iam_report
    from samoyed.credentials.aws import AwsCredential

    if not ping_emulator(endpoint_url=endpoint_url, region=region):
        typer.echo(f"Emulator not reachable at {endpoint_url}. Run: samoyed firing-range up", err=True)
        raise typer.Exit(1)
    if not credentials_file.is_file():
        typer.echo(f"Credentials missing: {credentials_file}. Run: samoyed firing-range seed", err=True)
        raise typer.Exit(1)

    data = json.loads(credentials_file.read_text(encoding="utf-8"))
    cred = AwsCredential(
        access_key=data["AccessKeyId"],
        secret_key=data["SecretAccessKey"],
        region=region,
        endpoint_url=data.get("endpoint_url") or endpoint_url,
    )
    report = collect_iam_report(cred)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    typer.echo(json.dumps({"output": str(output), "identities": len(report["identities"]), "grants": len(report["grants"])}, indent=2))


@app.command("collect-azure-report")
def collect_azure_report_cmd(
    output: Path = typer.Option(
        Path(".samoyed/azure/client-iam-report.json"),
        help="Where to write iam-report JSON",
    ),
    subscription_id: str | None = typer.Option(None, envvar="AZURE_SUBSCRIPTION_ID", help="Azure subscription ID"),
) -> None:
    """Collect iam-report JSON from live Azure APIs (requires az login or SP env vars)."""
    from samoyed.client.azure_report import collect_azure_iam_report

    try:
        cred = load_azure_credential(subscription_id=subscription_id)
    except ImportError:
        typer.echo("Install Azure support: pip install 'samoyed[azure]'", err=True)
        raise typer.Exit(1)
    except ValueError as exc:
        typer.echo(f"{exc}", err=True)
        typer.echo("Set AZURE_SUBSCRIPTION_ID and run az login or SP env vars.", err=True)
        raise typer.Exit(1)

    try:
        report = collect_azure_iam_report(cred)
    except Exception as exc:
        typer.echo(f"Collection failed: {exc}", err=True)
        raise typer.Exit(1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    typer.echo(
        json.dumps(
            {
                "output": str(output),
                "provider": report["provider"],
                "identities": len(report["identities"]),
                "resources": len(report["resources"]),
                "grants": len(report["grants"]),
            },
            indent=2,
        )
    )


@firing_range_app.command("probe-leaked")
def firing_range_probe_leaked_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
    credentials_file: Path = typer.Option(CREDENTIALS_FILE, help="Leaked user key JSON"),
    high_value_only: bool = typer.Option(False, "--high-value-only"),
    report_only: bool = typer.Option(False, "--report-only", help="Print probe JSON only"),
) -> None:
    """Run API probe catalog against leaked-user credentials on LocalStack."""
    from samoyed.credentials.aws import AwsCredential

    if not ping_emulator(endpoint_url=endpoint_url, region=region):
        typer.echo(f"Emulator not reachable at {endpoint_url}. Run: samoyed firing-range up", err=True)
        raise typer.Exit(1)
    if not credentials_file.is_file():
        typer.echo(f"Credentials missing: {credentials_file}. Run: samoyed firing-range seed", err=True)
        raise typer.Exit(1)

    data = json.loads(credentials_file.read_text(encoding="utf-8"))
    cred = AwsCredential(
        access_key=data["AccessKeyId"],
        secret_key=data["SecretAccessKey"],
        region=region,
        endpoint_url=data.get("endpoint_url") or endpoint_url,
    )
    probe_report = run_api_probes(cred, high_value_only=high_value_only)
    if report_only:
        typer.echo(json.dumps(probe_report.to_dict(), indent=2))
        return

    record = SESSION_STORE.create_probe_session(cred, high_value_only=high_value_only, with_enum=False)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Allowed: {len(probe_report.allowed)}  Denied: {len(probe_report.denied)}")
    typer.echo(json.dumps([r.operation for r in probe_report.allowed], indent=2))


@firing_range_app.command("export-aws-authz")
def firing_range_export_aws_authz_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
    output: Path = typer.Option(
        None,
        help="Output path (default: .samoyed/firing-range/aws-authz-details.json)",
    ),
    import_session: bool = typer.Option(False, "--import", help="Import into Samoyed session"),
) -> None:
    """Export iam:GetAccountAuthorizationDetails JSON (real AWS API used by IAM analysis tools)."""
    from samoyed.firing_range.aws_authz_export import export_account_authorization_details
    from samoyed.firing_range.config import AWS_AUTHZ_FILE, DEFAULT_ACCESS_KEY, DEFAULT_SECRET_KEY

    if not ping_emulator(endpoint_url=endpoint_url, region=region):
        typer.echo(f"Emulator not reachable at {endpoint_url}. Run: samoyed firing-range up", err=True)
        raise typer.Exit(1)

    out = output or AWS_AUTHZ_FILE
    payload = export_account_authorization_details(
        endpoint_url=endpoint_url,
        region=region,
        access_key=DEFAULT_ACCESS_KEY,
        secret_key=DEFAULT_SECRET_KEY,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    typer.echo(
        json.dumps(
            {
                "output": str(out),
                "users": len(payload.get("UserDetailList", [])),
                "roles": len(payload.get("RoleDetailList", [])),
            },
            indent=2,
        )
    )
    if import_session:
        record = SESSION_STORE.create_import_session("aws-authz-details", out.read_bytes())
        typer.echo(f"Imported session {record.session_id}")


@firing_range_app.command("scoutsuite")
def firing_range_scoutsuite_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
    report_dir: Path = typer.Option(SCOUTSUITE_DIR, help="ScoutSuite output directory"),
    import_session: bool = typer.Option(True, "--import/--no-import", help="Import scan into Samoyed session"),
    docker: bool = typer.Option(False, "--docker", help="Run ScoutSuite via Docker image"),
) -> None:
    """Run real ScoutSuite CLI (best on real AWS; LocalStack: prefer export-aws-authz)."""
    from samoyed.firing_range.config import DEFAULT_ACCESS_KEY, DEFAULT_SECRET_KEY

    if not ping_emulator(endpoint_url=endpoint_url, region=region):
        typer.echo(f"Emulator not reachable at {endpoint_url}. Run: samoyed firing-range up", err=True)
        raise typer.Exit(1)
    if not scoutsuite_available() and not docker:
        typer.echo("ScoutSuite not installed. Use --docker or: pip install scoutsuite", err=True)
        raise typer.Exit(1)

    try:
        meta = run_scoutsuite_scan(
            endpoint_url=endpoint_url,
            region=region,
            access_key=DEFAULT_ACCESS_KEY,
            secret_key=DEFAULT_SECRET_KEY,
            report_dir=report_dir,
            use_docker=docker,
        )
    except (ScoutSuiteNotInstalledError, ScoutSuiteScanError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)

    typer.echo(json.dumps(meta, indent=2))
    if import_session:
        payload = Path(meta["result_file"]).read_bytes()
        record = SESSION_STORE.create_import_session("scoutsuite", payload)
        typer.echo(f"Imported session {record.session_id} ({record.metadata.get('node_count')} nodes)")


@firing_range_app.command("collect-artifacts")
def firing_range_collect_artifacts_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
    output: Optional[Path] = typer.Option(
        None,
        help="Snapshot directory (default: .samoyed/firing-range/snapshots/<timestamp>)",
    ),
    reseed: bool = typer.Option(False, "--reseed", help="Re-seed lab before collecting"),
    import_sessions: bool = typer.Option(False, "--import", help="Import reports into Samoyed sessions"),
    no_latest: bool = typer.Option(False, "--no-latest", help="Skip updating snapshots/latest"),
) -> None:
    """Collect client report, authz export, probes, and inventory into a gitignored snapshot."""
    from samoyed.firing_range.collect import collect_firing_range_artifacts
    from samoyed.firing_range.config import LATEST_SNAPSHOT_DIR

    if not ping_emulator(endpoint_url=endpoint_url, region=region):
        typer.echo(f"Emulator not reachable at {endpoint_url}. Run: samoyed firing-range up", err=True)
        raise typer.Exit(1)
    if not reseed and not CREDENTIALS_FILE.is_file():
        typer.echo(f"Credentials missing: {CREDENTIALS_FILE}. Run: samoyed firing-range seed", err=True)
        raise typer.Exit(1)

    try:
        manifest = collect_firing_range_artifacts(
            endpoint_url=endpoint_url,
            region=region,
            output_dir=output,
            reseed=reseed,
            update_latest=not no_latest,
        )
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    except Exception as exc:
        typer.echo(f"Collect failed: {exc}", err=True)
        raise typer.Exit(1)

    typer.echo(json.dumps(manifest, indent=2))
    if not no_latest:
        typer.echo(f"Latest copy: {LATEST_SNAPSHOT_DIR}")

    if import_sessions:
        iam_bytes = Path(manifest["files"]["client_iam_report"]).read_bytes()
        iam_payload = json.loads(iam_bytes)
        iam_session = SESSION_STORE.create_import_session(
            "iam-report",
            iam_bytes,
            caller_arn=iam_payload.get("caller_arn"),
        )
        authz_session = SESSION_STORE.create_import_session(
            "aws-authz-details",
            Path(manifest["files"]["aws_authz_details"]).read_bytes(),
        )
        typer.echo(
            json.dumps(
                {
                    "iam_report_session": iam_session.session_id,
                    "aws_authz_session": authz_session.session_id,
                },
                indent=2,
            )
        )


@firing_range_app.command("verify")
def firing_range_verify_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
    scoutsuite_docker: bool = typer.Option(False, "--scoutsuite-docker", help="Attempt ScoutSuite via Docker"),
) -> None:
    """Run LocalStack lab workflows: client iam-report, leaked-key probes, aws-authz import."""
    from samoyed.client.iam_report import collect_iam_report
    from samoyed.credentials.aws import AwsCredential

    if not ping_emulator(endpoint_url=endpoint_url, region=region):
        typer.echo(f"Emulator not reachable at {endpoint_url}. Run: samoyed firing-range up && seed", err=True)
        raise typer.Exit(1)
    if not CREDENTIALS_FILE.is_file():
        typer.echo("Run: samoyed firing-range seed first", err=True)
        raise typer.Exit(1)

    results: dict[str, Any] = {}

    cred_data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
    cred = AwsCredential(
        access_key=cred_data["AccessKeyId"],
        secret_key=cred_data["SecretAccessKey"],
        region=region,
        endpoint_url=endpoint_url,
    )
    report = collect_iam_report(cred)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_IAM_REPORT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
    iam_session = SESSION_STORE.create_import_session(
        "iam-report",
        CLIENT_IAM_REPORT_FILE.read_bytes(),
        caller_arn=report["caller_arn"],
    )
    results["client_iam_report"] = {
        "file": str(CLIENT_IAM_REPORT_FILE),
        "session_id": iam_session.session_id,
        "grants": len(report["grants"]),
    }

    probe_report = run_api_probes(cred)
    probe_session = SESSION_STORE.create_probe_session(cred, with_enum=False)
    results["leaked_key_probes"] = {
        "session_id": probe_session.session_id,
        "allowed": len(probe_report.allowed),
        "allowed_ops": [r.operation for r in probe_report.allowed],
    }

    from samoyed.firing_range.aws_authz_export import export_account_authorization_details
    from samoyed.firing_range.config import AWS_AUTHZ_FILE, DEFAULT_ACCESS_KEY, DEFAULT_SECRET_KEY

    authz = export_account_authorization_details(
        endpoint_url=endpoint_url,
        region=region,
        access_key=DEFAULT_ACCESS_KEY,
        secret_key=DEFAULT_SECRET_KEY,
    )
    AWS_AUTHZ_FILE.write_text(json.dumps(authz, indent=2), encoding="utf-8")
    authz_session = SESSION_STORE.create_import_session("aws-authz-details", AWS_AUTHZ_FILE.read_bytes())
    results["aws_authz_details"] = {
        "file": str(AWS_AUTHZ_FILE),
        "session_id": authz_session.session_id,
        "users": len(authz.get("UserDetailList", [])),
        "roles": len(authz.get("RoleDetailList", [])),
    }

    if scoutsuite_available() or scoutsuite_docker:
        try:
            scan = run_scoutsuite_scan(
                endpoint_url=endpoint_url,
                region=region,
                access_key=DEFAULT_ACCESS_KEY,
                secret_key=DEFAULT_SECRET_KEY,
                report_dir=SCOUTSUITE_DIR,
                use_docker=scoutsuite_docker,
            )
            ss_session = SESSION_STORE.create_import_session(
                "scoutsuite",
                Path(scan["result_file"]).read_bytes(),
            )
            results["scoutsuite"] = {
                "result_file": scan["result_file"],
                "session_id": ss_session.session_id,
            }
        except (ScoutSuiteNotInstalledError, ScoutSuiteScanError) as exc:
            results["scoutsuite"] = {"skipped": str(exc)}
    else:
        results["scoutsuite"] = {"skipped": "use --scoutsuite-docker or pip install scoutsuite"}

    typer.echo(json.dumps(results, indent=2))


@firing_range_app.command("enum")
def firing_range_enum_cmd(
    endpoint_url: str = typer.Option(DEFAULT_ENDPOINT, help="Emulated AWS endpoint"),
    region: str = typer.Option(DEFAULT_REGION, help="AWS region"),
    with_probe: bool = typer.Option(False, "--with-probe", help="Also run API probes"),
) -> None:
    """Enumerate the emulated AWS lab (uses test/test credentials)."""
    from samoyed.credentials.aws import AwsCredential

    if not ping_emulator(endpoint_url=endpoint_url, region=region):
        typer.echo(f"Emulator not reachable at {endpoint_url}. Run: samoyed firing-range up", err=True)
        raise typer.Exit(1)
    cred = AwsCredential(
        access_key="test",
        secret_key="test",
        region=region,
        endpoint_url=endpoint_url,
    )
    if with_probe:
        record = SESSION_STORE.create_probe_session(cred, with_enum=True)
    else:
        record = SESSION_STORE.create_session(cred)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo("Run: samoyed scenario leaked-credential --session-id " + record.session_id)


@app.command("import-fixture")
def import_fixture_cmd(
    fixture_id: str = typer.Argument(..., help="Fixture id (lab-aws, enterprise-aws, k8s-lab, …)"),
    session_id: str | None = typer.Option(None, help="Optional session id override"),
) -> None:
    """Import a bundled field report through the connector pipeline (no cloud APIs)."""
    try:
        record = SESSION_STORE.load_fixture(fixture_id, session_id=session_id)
    except KeyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Fixture: {record.metadata.get('fixture_id')}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo(f"Source: {record.metadata.get('source')} ({record.metadata.get('collected_via', 'file')})")


@app.command("import-cartography")
def import_cartography_cmd(
    caller_arn: str | None = typer.Option(None, help="Principal ARN to treat as blast-radius start"),
    account_id: str | None = typer.Option(None, help="Filter to one AWS account id"),
    project_id: str | None = typer.Option(None, help="Filter to one GCP project id"),
    neo4j_uri: str | None = typer.Option(None, envvar="CARTOGRAPHY_NEO4J_URI", help="Cartography Neo4j bolt URI"),
    neo4j_user: str | None = typer.Option(None, envvar="CARTOGRAPHY_NEO4J_USER"),
    neo4j_password: str | None = typer.Option(None, envvar="CARTOGRAPHY_NEO4J_PASSWORD"),
    neo4j_database: str | None = typer.Option(None, envvar="CARTOGRAPHY_NEO4J_DATABASE"),
) -> None:
    """Import a Cartography Neo4j graph into a Samoyed attack-path session."""
    try:
        record = SESSION_STORE.create_cartography_session(
            caller_arn=caller_arn,
            account_id=account_id,
            project_id=project_id,
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
            neo4j_database=neo4j_database,
        )
    except Exception as exc:
        typer.echo(f"Cartography import failed: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo(f"Artifacts: {record.metadata.get('artifact_count', 0)}")
    typer.echo("Run: samoyed scenario leaked-credential --session-id " + record.session_id)


@app.command("cartography-status")
def cartography_status_cmd(
    neo4j_uri: str | None = typer.Option(None, envvar="CARTOGRAPHY_NEO4J_URI"),
    neo4j_user: str | None = typer.Option(None, envvar="CARTOGRAPHY_NEO4J_USER"),
    neo4j_password: str | None = typer.Option(None, envvar="CARTOGRAPHY_NEO4J_PASSWORD"),
    neo4j_database: str | None = typer.Option(None, envvar="CARTOGRAPHY_NEO4J_DATABASE"),
    account_id: str | None = typer.Option(None, help="Optional AWS account filter for stats"),
) -> None:
    """Show Cartography Neo4j connectivity and synced AWS account summary."""
    from samoyed.connectors.cartography.client import CartographyClient

    try:
        with CartographyClient(
            uri=neo4j_uri,
            user=neo4j_user,
            password=neo4j_password,
            database=neo4j_database,
        ) as client:
            if not client.ping():
                typer.echo("Neo4j reachable but ping failed", err=True)
                raise typer.Exit(1)
            accounts = client.list_aws_accounts()
            stats = client.stats(account_id=account_id)
    except Exception as exc:
        typer.echo(f"Cartography status failed: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps({"accounts": accounts, "stats": stats}, indent=2))


@app.command("whoami")
def whoami_cmd(
    provider: str = typer.Option("aws", help="Cloud provider (aws | kubernetes | gcp | azure)"),
    profile: str | None = typer.Option(None, help="AWS profile name"),
    key_file: Path | None = typer.Option(None, help="JSON key file"),
    region: str | None = typer.Option(None, help="AWS region"),
    endpoint_url: str | None = typer.Option(None, help="AWS API endpoint (e.g. Moto/LocalStack)"),
    kubeconfig: Path | None = typer.Option(None, help="Kubeconfig path"),
    context: str | None = typer.Option(None, help="Kubeconfig context"),
    project_id: str | None = typer.Option(None, help="GCP project ID"),
    subscription_id: str | None = typer.Option(None, help="Azure subscription ID"),
) -> None:
    """Print caller identity for configured credentials."""
    cred = _load_provider_credential(
        provider,
        profile=profile,
        key_file=key_file,
        region=region,
        endpoint_url=endpoint_url,
        kubeconfig=kubeconfig,
        context=context,
        project_id=project_id,
        subscription_id=subscription_id,
    )
    ident = cred.get_caller_identity()  # type: ignore[attr-defined]
    scope = cred.resolve_scope()
    typer.echo(json.dumps({"identity": ident, "scope": scope.__dict__}, indent=2, default=str))


@app.command("enum")
def enum_cmd(
    provider: str = typer.Option("aws", help="Cloud provider (aws | kubernetes | gcp | azure)"),
    profile: str | None = typer.Option(None, help="AWS profile name"),
    key_file: Path | None = typer.Option(None, help="JSON key file"),
    region: str | None = typer.Option(None, help="AWS region"),
    endpoint_url: str | None = typer.Option(None, help="AWS API endpoint (e.g. Moto/LocalStack)"),
    kubeconfig: Path | None = typer.Option(None, help="Kubeconfig path"),
    context: str | None = typer.Option(None, help="Kubeconfig context"),
    project_id: str | None = typer.Option(None, help="GCP project ID"),
    subscription_id: str | None = typer.Option(None, help="Azure subscription ID"),
    with_probe: bool = typer.Option(
        False,
        "--with-probe",
        help="Also brute-force API probes (for keys without IAM list access)",
    ),
    probe_only: bool = typer.Option(
        False,
        "--probe-only",
        help="Use API probing instead of IAM-based enumeration",
    ),
) -> None:
    """Run live enumeration and build attack-path graph."""
    cred = _load_provider_credential(
        provider,
        profile=profile,
        key_file=key_file,
        region=region,
        endpoint_url=endpoint_url,
        kubeconfig=kubeconfig,
        context=context,
        project_id=project_id,
        subscription_id=subscription_id,
    )
    if probe_only or with_probe:
        record = SESSION_STORE.create_probe_session(cred, with_enum=with_probe and not probe_only)
    else:
        record = SESSION_STORE.create_session(cred)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo(f"Denials: {len(record.denial_log.records)}")
    if record.metadata.get("allowed_operations"):
        typer.echo(f"Probed APIs (allowed): {len(record.metadata['allowed_operations'])}")


@app.command("probe")
def probe_cmd(
    provider: str = typer.Option("aws", help="Cloud provider (aws | gcp | azure)"),
    profile: str | None = typer.Option(None, help="AWS profile name"),
    key_file: Path | None = typer.Option(None, help="JSON key file"),
    region: str | None = typer.Option(None, help="AWS region"),
    endpoint_url: str | None = typer.Option(None, help="AWS API endpoint"),
    project_id: str | None = typer.Option(None, help="GCP project ID"),
    subscription_id: str | None = typer.Option(None, help="Azure subscription ID"),
    high_value_only: bool = typer.Option(False, help="Only probe high-value APIs"),
    report_only: bool = typer.Option(False, help="Print probe report JSON without building a session"),
    list_catalog: bool = typer.Option(False, "--list", help="List probe operations and exit"),
    with_enum: bool = typer.Option(False, help="After probing, also run IAM-based enum where allowed"),
) -> None:
    """
    Brute-force cloud API access with leaked/low-privilege credentials.

    Use when keys cannot call IAM list/get APIs. Successful probes become graph edges.
    """
    if list_catalog:
        prov = CloudProvider(provider)
        for probe in get_probe_catalog(prov, high_value_only=high_value_only):
            flag = " *" if probe.high_value else ""
            typer.echo(f"{probe.operation}{flag} — {probe.description}")
        return

    cred = _load_provider_credential(
        provider,
        profile=profile,
        key_file=key_file,
        region=region,
        endpoint_url=endpoint_url,
        project_id=project_id,
        subscription_id=subscription_id,
    )

    if report_only:
        report = run_api_probes(cred, high_value_only=high_value_only)
        typer.echo(json.dumps(report.to_dict(), indent=2, default=str))
        return

    record = SESSION_STORE.create_probe_session(
        cred, high_value_only=high_value_only, with_enum=with_enum
    )
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Allowed APIs: {record.metadata.get('allowed_operations', [])}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo(f"Denied probes: {len(record.denial_log.records)}")


@app.command("scenario")
def scenario_cmd(
    name: str = typer.Argument("leaked-credential"),
    session_id: str | None = typer.Option(None, help="Session id, short name, or omit for most recent"),
    start: str | None = typer.Option(None, "--as", help="Compromised principal ARN or node id"),
    provider: str = typer.Option("aws"),
    profile: str | None = typer.Option(None),
    key_file: Path | None = typer.Option(None),
) -> None:
    """Run a blast-radius scenario."""
    from samoyed.path_engine.format import format_path_query_response

    if not session_id:
        session = SESSION_STORE.resolve_session_ref()
        if not session and provider == "aws":
            cred = load_aws_credential(profile=profile, key_file=key_file)
            session = SESSION_STORE.create_session(cred)
            typer.echo(f"Created session {session.session_id} ({session.metadata.get('short_name')})")
        elif not session:
            typer.echo("No session found; run enum/import first or pass --session-id", err=True)
            raise typer.Exit(1)
    else:
        session = SESSION_STORE.resolve_session_ref(session_id)
        if not session:
            typer.echo(f"Session not found: {session_id}", err=True)
            raise typer.Exit(1)

    session_id = session.session_id
    start_node = SESSION_STORE.resolve_start_node(session_id, start) if start else None
    paths = SESSION_STORE.run_scenario(session_id, name, start_node_id=start_node)
    if not start_node:
        start_node = SESSION_STORE.find_caller_node(session) or ""
    payload = format_path_query_response(
        session_id=session_id,
        graph=session.snapshot,
        start_node_id=start_node,
        mode="blast" if name == "leaked-credential" else name,
        raw={"paths": [_path_to_dict(p) for p in paths]},
        query={"scenario": name, "start": start},
    )
    typer.echo(json.dumps(payload, indent=2, default=str))


@app.command("paths")
def paths_cmd(
    session_id: str | None = typer.Argument(None, help="Session id, short name, or omit for most recent"),
    target_concept: str | None = typer.Option(None),
    target_resource_type: str | None = typer.Option(None),
    max_depth: int = typer.Option(6),
) -> None:
    """Query attack paths for a session."""
    session = SESSION_STORE.resolve_session_ref(session_id)
    if not session:
        typer.echo("Session not found", err=True)
        raise typer.Exit(1)
    results = SESSION_STORE.query_paths(
        session.session_id,
        target_concept=target_concept,
        target_resource_type=target_resource_type,
        max_depth=max_depth,
    )
    typer.echo(json.dumps([_path_to_dict(p) for p in results], indent=2, default=str))


@sessions_app.command("clear")
def sessions_clear_cmd(
    include_demos: bool = typer.Option(False, "--include-demos", help="Also delete demo/fixture sessions"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Delete persisted attack-graph sessions from ~/.samoyed/sessions (or SAMOYED_HOME)."""
    if not yes and not typer.confirm("Delete all non-demo sessions?", default=False):
        raise typer.Abort()
    result = SESSION_STORE.clear_sessions(include_demos=include_demos)
    typer.echo(json.dumps(result, indent=2))


@sessions_app.command("delete")
def sessions_delete_cmd(
    session_ref: str = typer.Argument(..., help="Session id or short name"),
    include_demo: bool = typer.Option(False, "--include-demo", help="Allow deleting demo/fixture sessions"),
) -> None:
    """Delete one persisted session."""
    try:
        result = SESSION_STORE.delete_session(session_ref, allow_demo=include_demo)
    except KeyError:
        typer.echo(f"Session not found: {session_ref}", err=True)
        raise typer.Exit(1)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps(result, indent=2))


@app.command("ui")
def ui_cmd(
    host: str = typer.Option("127.0.0.1", help="Bind address"),
    port: int = typer.Option(8000, help="HTTP port"),
    username: str | None = typer.Option(None, envvar="SAMOYED_USERNAME", help="UI login username"),
    password: str | None = typer.Option(None, envvar="SAMOYED_PASSWORD", help="UI login password"),
    api_token: str | None = typer.Option(None, envvar="SAMOYED_API_TOKEN", help="Optional API bearer token"),
) -> None:
    """Start API + web UI."""
    import secrets

    from samoyed.api.auth import configure_auth, get_auth_settings

    if host not in ("127.0.0.1", "localhost") and not password and not api_token:
        password = secrets.token_urlsafe(18)
        typer.echo(f"Non-localhost bind — generated SAMOYED_PASSWORD: {password}", err=True)
    configure_auth(username=username, password=password, api_token=api_token)
    settings = get_auth_settings()
    if not settings.enabled:
        typer.echo(
            "Warning: set SAMOYED_PASSWORD (or SAMOYED_API_TOKEN) to require login on the UI/API.",
            err=True,
        )
    uvicorn.run("samoyed.api.main:app", host=host, port=port, reload=False)


@app.command("mcp")
def mcp_cmd() -> None:
    """Start stdio MCP server for agent queries."""
    try:
        from samoyed.mcp.server import main as mcp_main
    except ImportError:
        typer.echo("Install MCP support: pip install 'samoyed[mcp]'", err=True)
        raise typer.Exit(1)
    mcp_main()


@app.command("init-extension")
def init_extension_cmd(
    kind: str = typer.Argument(..., help="enumerator | connector | scenario"),
    name: str = typer.Argument(..., help="Extension name"),
) -> None:
    """Scaffold a custom extension in .samoyed/."""
    path = init_extension(kind, name)
    typer.echo(f"Created {path}")


def _load_provider_credential(provider: str, **kwargs):
    try:
        if provider == "kubernetes":
            return load_k8s_credential(
                kubeconfig=kwargs.get("kubeconfig"),
                context=kwargs.get("context"),
            )
        if provider == "gcp":
            return load_gcp_credential(
                key_file=kwargs.get("key_file"),
                project_id=kwargs.get("project_id"),
            )
        if provider == "azure":
            return load_azure_credential(subscription_id=kwargs.get("subscription_id"))
        if provider == "aws":
            return load_aws_credential(
                profile=kwargs.get("profile"),
                key_file=kwargs.get("key_file"),
                region=kwargs.get("region"),
                endpoint_url=kwargs.get("endpoint_url"),
            )
    except ImportError as exc:
        extra = {"kubernetes": "k8s", "gcp": "gcp", "azure": "azure"}.get(provider, "dev")
        typer.echo(f"Install support: pip install 'samoyed[{extra}]' ({exc})", err=True)
        raise typer.Exit(1)
    typer.echo(f"Provider {provider} not supported", err=True)
    raise typer.Exit(1)


def _path_to_dict(p) -> dict:
    return {
        "path_id": p.path_id,
        "score": p.score,
        "node_ids": p.node_ids,
        "target_match": p.target_match,
        "steps": [
            {"step": s.step_index, "src": s.src_id, "rel": s.rel_type, "dst": s.dst_id}
            for s in p.steps
        ],
    }


@app.command("enrich")
def enrich_cmd(
    file: Path = typer.Argument(..., help="Enrichment report JSON (bindings use target_ref)"),
    session: Optional[str] = typer.Option(
        None,
        "--session",
        "-s",
        help="Session id or short name (default: most recent)",
    ),
) -> None:
    """Apply a collector enrichment file to the attack graph."""
    if not file.is_file():
        typer.echo(f"File not found: {file}", err=True)
        raise typer.Exit(1)

    record = SESSION_STORE.resolve_session_ref(session)
    if not record:
        typer.echo("No session found — import or enum first, or pass --session", err=True)
        raise typer.Exit(1)

    try:
        stats = SESSION_STORE.apply_enrichment(record.session_id, file.read_bytes())
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)

    if stats.get("unresolved_bindings"):
        typer.echo(
            json.dumps(
                {
                    "session_id": record.session_id,
                    "warning": "Some bindings could not be matched to graph nodes",
                    **stats,
                },
                indent=2,
            ),
            err=True,
        )
        raise typer.Exit(2)

    typer.echo(
        json.dumps(
            {
                "session_id": record.session_id,
                "file": str(file),
                **stats,
            },
            indent=2,
        )
    )


@collect_app.command("static")
def collect_static_cmd(
    path: Path = typer.Argument(..., help="Repo or config directory to scan"),
    target_ref: str = typer.Option(
        ...,
        "--bind-ref",
        help="Graph node ref for findings (native_id, ARN, or name)",
    ),
    output: Path = typer.Option(
        Path("enrichment.json"),
        "--output",
        "-o",
        help="Where to write enrichment report JSON",
    ),
    resolves_to: Optional[str] = typer.Option(
        None,
        help="Optional identity native_id/ARN to attach when rules find credentials",
    ),
    collector: str = typer.Option(
        "static-repo",
        help="Collector label (static-repo, static-config, …)",
    ),
) -> None:
    """Scan static files (configs, repos) and write an enrichment report."""
    from samoyed.collectors.static import collect_static_source

    try:
        report = collect_static_source(
            path,
            target_ref=target_ref,
            collector_name=collector,
            resolves_to=resolves_to,
        )
    except FileNotFoundError:
        typer.echo(f"Path not found: {path}", err=True)
        raise typer.Exit(1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    typer.echo(
        json.dumps(
            {
                "output": str(output),
                "source_root": report.get("source_root"),
                "files_scanned": report.get("files_scanned"),
                "material_count": report.get("material_count"),
                "target_ref": target_ref,
                "hint": f"samoyed enrich {output}",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    app()
