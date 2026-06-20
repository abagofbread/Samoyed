from __future__ import annotations

from pathlib import Path
from typing import Any

from samoyed.cloud.artifacts import ConceptArtifact, DenialLog, DenialRecord
from samoyed.cloud.concepts import CloudProvider
from samoyed.credentials.protocol import CloudCredential
from samoyed.probes.aws import (
    artifacts_from_aws_probes,
    aws_probe_catalog,
    run_aws_probe,
)
from samoyed.probes.azure import (
    artifacts_from_azure_probes,
    azure_probe_catalog,
    run_azure_probe,
)
from samoyed.probes.gcp import (
    artifacts_from_gcp_probes,
    gcp_probe_catalog,
    run_gcp_probe,
)
from samoyed.probes.models import ApiProbe, ProbeReport, ProbeResult
from samoyed.probes.scope import caller_native_id, resolve_scope_best_effort


def get_probe_catalog(provider: CloudProvider, *, high_value_only: bool = False) -> list[ApiProbe]:
    if provider == CloudProvider.AWS:
        return aws_probe_catalog(high_value_only=high_value_only)
    if provider == CloudProvider.GCP:
        return gcp_probe_catalog(high_value_only=high_value_only)
    if provider == CloudProvider.AZURE:
        return azure_probe_catalog(high_value_only=high_value_only)
    return []


def run_api_probes(
    credentials: CloudCredential,
    *,
    high_value_only: bool = False,
    operations: list[str] | None = None,
) -> ProbeReport:
    scope = resolve_scope_best_effort(credentials)
    caller_id = caller_native_id(scope)
    catalog = get_probe_catalog(credentials.provider, high_value_only=high_value_only)
    if credentials.provider == CloudProvider.AWS:
        catalog = catalog + load_custom_probes()
    if operations:
        op_set = set(operations)
        catalog = [p for p in catalog if p.operation in op_set]

    results: list[ProbeResult] = []
    for probe in catalog:
        results.append(_run_single_probe(credentials, probe))

    # Refresh caller if STS probe succeeded (AWS)
    for result in results:
        if result.operation == "sts:GetCallerIdentity" and result.status == "allowed":
            ident = result.metadata.get("identity", {})
            if ident.get("Arn"):
                caller_id = ident["Arn"]
                scope.properties["arn"] = caller_id
                scope.properties["native_id"] = caller_id
                scope.properties["account_id"] = ident.get("Account")

    return ProbeReport(
        provider=credentials.provider,
        caller_native_id=caller_id,
        scope_id=scope.scope_id,
        results=results,
    )


def _run_single_probe(credentials: CloudCredential, probe: ApiProbe) -> ProbeResult:
    provider = credentials.provider
    if provider == CloudProvider.AWS:
        return run_aws_probe(credentials, probe)
    if provider == CloudProvider.GCP:
        return run_gcp_probe(credentials, probe)
    if provider == CloudProvider.AZURE:
        return run_azure_probe(credentials, probe)
    return ProbeResult(probe.operation, "error", message=f"Unsupported provider: {provider}")


def probe_to_artifacts(report: ProbeReport, scope: Any) -> list[ConceptArtifact]:
    scope_id = report.scope_id
    caller_id = report.caller_native_id
    results = report.results

    if report.provider == CloudProvider.AWS:
        kind = "Unknown"
        if ":user/" in caller_id:
            kind = "User"
        elif ":role/" in caller_id:
            kind = "Role"
        elif caller_id.startswith("aws:access-key:"):
            kind = "AccessKey"
        return list(
            artifacts_from_aws_probes(
                scope_id=scope_id,
                caller_id=caller_id,
                caller_kind=kind,
                results=results,
            )
        )

    if report.provider == CloudProvider.GCP:
        return list(artifacts_from_gcp_probes(scope_id=scope_id, caller_id=caller_id, results=results))

    if report.provider == CloudProvider.AZURE:
        return list(artifacts_from_azure_probes(scope_id=scope_id, caller_id=caller_id, results=results))

    return []


def load_custom_probes(path: Path | None = None) -> list[ApiProbe]:
    """Optional `.samoyed/probes.json` with extra operations to attempt."""
    probe_file = path or Path.cwd() / ".samoyed" / "probes.json"
    if not probe_file.is_file():
        return []
    import json

    data = json.loads(probe_file.read_text(encoding="utf-8"))
    out: list[ApiProbe] = []
    for item in data.get("probes", []):
        from samoyed.cloud.concepts import CapabilityType

        cap = CapabilityType(item.get("capability", "READS"))
        out.append(
            ApiProbe(
                operation=item["operation"],
                description=item.get("description", item["operation"]),
                capability=cap,
                resource_type=item.get("resource_type"),
                concept_type=item.get("concept_type"),
                high_value=bool(item.get("high_value", False)),
            )
        )
    return out


def probe_denial_log(report: ProbeReport) -> DenialLog:
    log = DenialLog()
    for result in report.results:
        if result.status == "denied":
            log.add(
                DenialRecord(
                    provider=report.provider,
                    operation=result.operation,
                    error_code=result.error_code or "AccessDenied",
                    message=result.message,
                )
            )
    return log
