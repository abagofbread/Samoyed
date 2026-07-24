from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence, DenialRecord
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.gcp import sa_native_id
from samoyed.credentials.protocol import EnumContext


class GcpComputeEnumerator:
    concept = ConceptType.RUNTIME_BINDING
    name = "gcp-compute"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        project = ctx.scope.properties.get("project_id", "")
        cred = ctx.credentials
        functions = _list_cloud_functions(cred, project, ctx)
        for fn in functions:
            name = fn.get("name", "")
            short = name.split("/")[-1] if name else "unknown"
            sa_email = fn.get("serviceAccountEmail") or (fn.get("serviceConfig") or {}).get(
                "serviceAccountEmail"
            )
            sa_native = sa_native_id(sa_email) if sa_email else None
            edges: list[ConceptEdge] = []
            if sa_native:
                edges.append(
                    ConceptEdge(
                        rel_type="EXECUTES_AS",
                        target_native_id=sa_native,
                        target_concept_type=ConceptType.IDENTITY,
                        props={"service_account": sa_email, "resource_type": "CloudFunction"},
                    )
                )
            native_id = f"CloudFunction:{name or short}"
            yield ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.GCP,
                native_id=native_id,
                scope_id=ctx.scope.scope_id,
                properties={
                    "resource_type": "CloudFunction",
                    "name": short,
                    "full_name": name,
                    "service_account_email": sa_email,
                    "execution_identity": sa_native,
                    "https_trigger": fn.get("httpsTrigger") is not None or fn.get("uri"),
                },
                evidence=Evidence("cloudfunctions.functions.list", {"name": name}),
                edges=edges,
            )
        for service in _list_google_api(
            cred, f"https://run.googleapis.com/v2/projects/{project}/locations/-/services", "services", ctx, "run.services.list"
        ):
            yield _runtime_artifact(
                ctx, "CloudRunService", service.get("name", ""), service.get("template", {}).get("serviceAccount"),
                "run.services.list", extra={"uri": service.get("uri")},
            )
        for instance in _list_google_api(
            cred, f"https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances", "items", ctx, "compute.instances.aggregatedList"
        ):
            # Aggregated Compute API returns zone -> {instances: [...]}; flatten below.
            for item in instance.get("instances", []):
                sa = ((item.get("serviceAccounts") or [{}])[0]).get("email")
                yield _runtime_artifact(
                    ctx, "GCEInstance", item.get("selfLink") or item.get("name", ""), sa,
                    "compute.instances.aggregatedList", extra={"zone": item.get("zone")},
                )
        for build in _list_google_api(
            cred, f"https://cloudbuild.googleapis.com/v1/projects/{project}/builds", "builds", ctx, "cloudbuild.builds.list"
        ):
            sa = build.get("serviceAccount")
            yield _runtime_artifact(
                ctx, "CloudBuild", build.get("id", ""), sa, "cloudbuild.builds.list",
                extra={"uses_default_service_account": not bool(sa), "status": (build.get("status") or "")},
            )


def _list_cloud_functions(cred: object, project: str, ctx: EnumContext) -> list[dict]:
    return _list_google_api(
        cred,
        f"https://cloudfunctions.googleapis.com/v2/projects/{project}/locations/-/functions",
        "functions",
        ctx,
        "cloudfunctions.functions.list",
    )


def _list_google_api(
    cred: object, url: str, result_key: str, ctx: EnumContext, operation: str
) -> list[dict]:
    try:
        from google.auth.transport.requests import AuthorizedSession
    except ImportError:
        return []

    try:
        session = AuthorizedSession(cred.credentials())  # type: ignore[attr-defined]
    except Exception:
        return []

    try:
        resp = session.get(url, timeout=30)
        if resp.status_code in {401, 403}:
            ctx.denial_log.add(
                DenialRecord(
                    provider=CloudProvider.GCP,
                    operation=operation,
                    error_code=str(resp.status_code),
                    message=resp.text[:200],
                )
            )
            return []
        resp.raise_for_status()
        return list(resp.json().get(result_key, []))
    except Exception as exc:
        if "403" in str(exc) or "Permission" in str(exc):
            return []
        return []


def _runtime_artifact(
    ctx: EnumContext,
    resource_type: str,
    name: str,
    sa_email: str | None,
    operation: str,
    *,
    extra: dict | None = None,
) -> ConceptArtifact:
    short = name.rsplit("/", 1)[-1] or "unknown"
    sa_native = sa_native_id(sa_email) if sa_email else None
    edges = [
        ConceptEdge(
            rel_type="EXECUTES_AS",
            target_native_id=sa_native,
            target_concept_type=ConceptType.IDENTITY,
            props={"service_account": sa_email, "resource_type": resource_type},
        )
    ] if sa_native else []
    return ConceptArtifact(
        concept_type=ConceptType.RUNTIME_BINDING,
        provider=CloudProvider.GCP,
        native_id=f"{resource_type}:{name or short}",
        scope_id=ctx.scope.scope_id,
        properties={
            "resource_type": resource_type,
            "name": short,
            "full_name": name,
            "service_account_email": sa_email,
            "execution_identity": sa_native,
            **(extra or {}),
        },
        evidence=Evidence(operation, {"name": name}),
        edges=edges,
    )
