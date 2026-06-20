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


def _list_cloud_functions(cred: object, project: str, ctx: EnumContext) -> list[dict]:
    try:
        from google.auth.transport.requests import AuthorizedSession
    except ImportError:
        return []

    try:
        session = AuthorizedSession(cred.credentials())  # type: ignore[attr-defined]
    except Exception:
        return []

    parent = f"projects/{project}/locations/-"
    url = f"https://cloudfunctions.googleapis.com/v2/{parent}/functions"
    try:
        resp = session.get(url, timeout=30)
        if resp.status_code in {401, 403}:
            ctx.denial_log.add(
                DenialRecord(
                    provider=CloudProvider.GCP,
                    operation="cloudfunctions.functions.list",
                    error_code=str(resp.status_code),
                    message=resp.text[:200],
                )
            )
            return []
        resp.raise_for_status()
        return list(resp.json().get("functions", []))
    except Exception as exc:
        if "403" in str(exc) or "Permission" in str(exc):
            return []
        return []
