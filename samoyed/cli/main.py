from __future__ import annotations

import json
from pathlib import Path

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
    DEFAULT_ENDPOINT,
    DEFAULT_REGION,
    compose_down,
    compose_up,
    ping_emulator,
    seed_aws_lab,
)
from samoyed.sessions import SESSION_STORE
from samoyed.cloud.concepts import CloudProvider

app = typer.Typer(no_args_is_help=True, help="Samoyed — BloodHound for cloud")
firing_range_app = typer.Typer(help="Emulated vulnerable clouds (LocalStack, no lab data in repo)")
app.add_typer(firing_range_app, name="firing-range")


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


@app.command("load-sample")
def load_sample_cmd(session_id: str = typer.Option("sample-lab", help="Session ID for sample graph")) -> None:
    """Load offline sample graph (no cloud APIs required)."""
    record = SESSION_STORE.load_sample_session(session_id)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo("Run: samoyed scenario leaked-credential --session-id " + record.session_id)


@app.command("load-sample-k8s")
def load_sample_k8s_cmd(session_id: str = typer.Option("sample-k8s", help="Session ID for K8s sample graph")) -> None:
    """Load offline Kubernetes sample graph (no cluster required)."""
    record = SESSION_STORE.load_sample_k8s_session(session_id)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo("Run: samoyed scenario compromised-sa --session-id " + record.session_id)
    typer.echo("Run: samoyed scenario pod-escape --session-id " + record.session_id)


@app.command("load-sample-gcp")
def load_sample_gcp_cmd(session_id: str = typer.Option("sample-gcp", help="Session ID for GCP sample graph")) -> None:
    """Load offline GCP sample graph (no cloud account required)."""
    record = SESSION_STORE.load_sample_gcp_session(session_id)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo("Run: samoyed scenario leaked-credential --session-id " + record.session_id)


@app.command("load-sample-azure")
def load_sample_azure_cmd(session_id: str = typer.Option("sample-azure", help="Session ID for Azure sample graph")) -> None:
    """Load offline Azure sample graph (no cloud account required)."""
    record = SESSION_STORE.load_sample_azure_session(session_id)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo("Run: samoyed scenario leaked-credential --session-id " + record.session_id)


@app.command("load-sample-host")
def load_sample_host_cmd(session_id: str = typer.Option("sample-host", help="Session ID for host compromise sample graph")) -> None:
    """Load offline host-compromise sample (multi-hop laptop → cloud pivot)."""
    record = SESSION_STORE.load_sample_host_session(session_id)
    typer.echo(f"Session {record.session_id}")
    typer.echo(f"Caller: {record.caller_arn}")
    typer.echo(f"Nodes: {record.metadata.get('node_count', 0)}")
    typer.echo("Run: samoyed scenario host-compromise --session-id " + record.session_id)


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
    session_id: str | None = typer.Option(None, help="Existing session ID"),
    provider: str = typer.Option("aws"),
    profile: str | None = typer.Option(None),
    key_file: Path | None = typer.Option(None),
) -> None:
    """Run a blast-radius scenario."""
    if not session_id:
        if provider != "aws":
            raise typer.Exit(1)
        cred = load_aws_credential(profile=profile, key_file=key_file)
        record = SESSION_STORE.create_session(cred)
        session_id = record.session_id
        typer.echo(f"Created session {session_id}")

    paths = SESSION_STORE.run_scenario(session_id, name)
    typer.echo(json.dumps([_path_to_dict(p) for p in paths], indent=2, default=str))


@app.command("paths")
def paths_cmd(
    session_id: str = typer.Argument(...),
    target_concept: str | None = typer.Option(None),
    target_resource_type: str | None = typer.Option(None),
    max_depth: int = typer.Option(6),
) -> None:
    """Query attack paths for a session."""
    results = SESSION_STORE.query_paths(
        session_id,
        target_concept=target_concept,
        target_resource_type=target_resource_type,
        max_depth=max_depth,
    )
    typer.echo(json.dumps([_path_to_dict(p) for p in results], indent=2, default=str))


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


if __name__ == "__main__":
    app()
