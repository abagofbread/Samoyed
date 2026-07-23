from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from samoyed.api.auth import LoginRequest, auth_status_payload, login, logout
from samoyed.api.middleware import AuthMiddleware
from samoyed.api.search_suggestions import suggest_searches
from samoyed.cloud.ontology import export_ontology
from samoyed.credentials.loader import (
    load_aws_credential,
    load_azure_credential,
    load_gcp_credential,
    load_k8s_credential,
)
from samoyed.sessions import SESSION_STORE

app = FastAPI(title="Samoyed", version="0.1.0")
app.add_middleware(AuthMiddleware)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _resolve_session_ref(session_ref: str | None):
    record = SESSION_STORE.resolve_session_ref(session_ref)
    if not record:
        raise HTTPException(404, "Session not found")
    return record


class CartographyImportRequest(BaseModel):
    caller_arn: str | None = None
    account_id: str | None = None
    project_id: str | None = None
    neo4j_uri: str | None = None
    neo4j_user: str | None = None
    neo4j_password: str | None = None
    neo4j_database: str | None = None
    provider: str = "aws"


class EnumRequest(BaseModel):
    provider: str = "aws"
    profile: str | None = None
    kubeconfig: str | None = None
    context: str | None = None
    key_file: str | None = None
    project_id: str | None = None
    subscription_id: str | None = None
    probe_only: bool = False
    with_probe: bool = False


class ProbeRequest(BaseModel):
    provider: str = "aws"
    profile: str | None = None
    key_file: str | None = None
    project_id: str | None = None
    subscription_id: str | None = None
    high_value_only: bool = False
    with_enum: bool = False
    report_only: bool = False


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "samoyed"}


@app.get("/api/auth/status")
def auth_status(request: Request):
    return auth_status_payload(request)


@app.post("/api/auth/login")
def auth_login(req: LoginRequest, response: Response):
    return login(req, response)


@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    return logout(request, response)


@app.post("/api/sessions/cartography")
def create_cartography_session(req: CartographyImportRequest):
    from samoyed.cloud.concepts import CloudProvider

    try:
        provider = CloudProvider(req.provider)
    except ValueError:
        raise HTTPException(400, f"Unknown provider: {req.provider}")
    try:
        record = SESSION_STORE.create_cartography_session(
            caller_arn=req.caller_arn,
            account_id=req.account_id,
            project_id=req.project_id,
            neo4j_uri=req.neo4j_uri,
            neo4j_user=req.neo4j_user,
            neo4j_password=req.neo4j_password,
            neo4j_database=req.neo4j_database,
            provider=provider,
        )
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
        "metadata": record.metadata,
    }


@app.get("/api/connectors/cartography/status")
def cartography_status(
    account_id: str | None = None,
    neo4j_uri: str | None = None,
    neo4j_user: str | None = None,
    neo4j_password: str | None = None,
    neo4j_database: str | None = None,
):
    from samoyed.connectors.cartography.client import CartographyClient

    try:
        with CartographyClient(
            uri=neo4j_uri,
            user=neo4j_user,
            password=neo4j_password,
            database=neo4j_database,
        ) as client:
            return {
                "ok": client.ping(),
                "accounts": client.list_aws_accounts(),
                "stats": client.stats(account_id=account_id),
            }
    except Exception as exc:
        raise HTTPException(503, str(exc))


@app.post("/api/sessions")
def create_session(req: EnumRequest):
    if req.provider == "kubernetes":
        try:
            cred = load_k8s_credential(
                kubeconfig=Path(req.kubeconfig) if req.kubeconfig else None,
                context=req.context,
            )
        except ImportError:
            raise HTTPException(400, "Install Kubernetes support: pip install 'samoyed[k8s]'")
    elif req.provider == "gcp":
        try:
            cred = load_gcp_credential(
                key_file=Path(req.key_file) if req.key_file else None,
                project_id=req.project_id,
            )
        except ImportError:
            raise HTTPException(400, "Install GCP support: pip install 'samoyed[gcp]'")
    elif req.provider == "azure":
        try:
            cred = load_azure_credential(subscription_id=req.subscription_id)
        except ImportError:
            raise HTTPException(400, "Install Azure support: pip install 'samoyed[azure]'")
    elif req.provider == "aws":
        cred = load_aws_credential(profile=req.profile)
    else:
        raise HTTPException(400, f"Unsupported provider: {req.provider}")
    if req.probe_only or req.with_probe:
        record = SESSION_STORE.create_probe_session(cred, with_enum=req.with_probe and not req.probe_only)
    else:
        record = SESSION_STORE.create_session(cred)
    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
        "metadata": record.metadata,
        "denial_count": len(record.denial_log.records),
        "allowed_operations": record.metadata.get("allowed_operations"),
    }


@app.post("/api/sessions/probe")
def create_probe_session(req: ProbeRequest):
    if req.provider == "kubernetes":
        raise HTTPException(400, "Use enum for kubernetes; probe supports aws, gcp, azure")
    if req.provider == "gcp":
        try:
            cred = load_gcp_credential(
                key_file=Path(req.key_file) if req.key_file else None,
                project_id=req.project_id,
            )
        except ImportError:
            raise HTTPException(400, "Install GCP support: pip install 'samoyed[gcp]'")
    elif req.provider == "azure":
        try:
            cred = load_azure_credential(subscription_id=req.subscription_id)
        except ImportError:
            raise HTTPException(400, "Install Azure support: pip install 'samoyed[azure]'")
    elif req.provider == "aws":
        cred = load_aws_credential(
            profile=req.profile,
            key_file=Path(req.key_file) if req.key_file else None,
        )
    else:
        raise HTTPException(400, f"Unsupported provider: {req.provider}")

    if req.report_only:
        from samoyed.probes.runner import run_api_probes

        report = run_api_probes(cred, high_value_only=req.high_value_only)
        return report.to_dict()

    record = SESSION_STORE.create_probe_session(
        cred, high_value_only=req.high_value_only, with_enum=req.with_enum
    )
    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
        "metadata": record.metadata,
        "denial_count": len(record.denial_log.records),
        "allowed_operations": record.metadata.get("allowed_operations"),
    }


@app.get("/api/probes/catalog")
def probe_catalog(provider: str = "aws", high_value_only: bool = False):
    from samoyed.cloud.concepts import CloudProvider
    from samoyed.probes.runner import get_probe_catalog

    try:
        prov = CloudProvider(provider)
    except ValueError:
        raise HTTPException(400, f"Unknown provider: {provider}")
    return [
        {
            "operation": p.operation,
            "description": p.description,
            "capability": p.capability.value,
            "resource_type": p.resource_type,
            "high_value": p.high_value,
        }
        for p in get_probe_catalog(prov, high_value_only=high_value_only)
    ]


@app.get("/api/connectors")
def list_connectors():
    from samoyed.connectors.registry import list_connectors as registry_list

    return registry_list()


@app.post("/api/sessions/import")
async def import_session_report(
    connector: str = Form(...),
    file: UploadFile = File(...),
    caller_arn: str | None = Form(None),
):
    from samoyed.connectors.registry import CONNECTORS

    if connector not in CONNECTORS:
        raise HTTPException(400, f"Unknown connector: {connector}")
    if not CONNECTORS[connector].get("file_import"):
        raise HTTPException(400, f"Connector {connector} does not accept file upload")

    payload = await file.read()
    if not payload:
        raise HTTPException(400, "Empty file")

    try:
        record = SESSION_STORE.create_import_session(
            connector,
            payload,
            caller_arn=caller_arn or None,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")

    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
        "metadata": record.metadata,
    }


@app.post("/api/sessions/{session_id}/network")
async def attach_network_inventory(
    session_id: str,
    connector: str = Form("network-inventory"),
    file: UploadFile = File(...),
):
    """Merge Terraform/network-inventory facts into an existing session."""
    if connector not in {"network-inventory", "terraform"}:
        raise HTTPException(400, "connector must be network-inventory or terraform")
    payload = await file.read()
    if not payload:
        raise HTTPException(400, "Empty file")
    try:
        result = SESSION_STORE.attach_network_inventory(
            session_id, payload, connector_id=connector
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    return result


@app.get("/api/sessions")
def list_sessions(
    scope: str = Query("recent", pattern="^(recent|all|ids)$"),
    limit: int | None = Query(None, ge=1, le=500),
    include_demos: bool = Query(False),
    ids: str | None = Query(None, description="Comma-separated session IDs when scope=ids"),
):
    session_ids = [part.strip() for part in ids.split(",") if part.strip()] if ids else None
    if scope == "ids" and not session_ids:
        raise HTTPException(400, "scope=ids requires ids parameter")
    effective_limit = limit if limit is not None else (500 if scope == "all" else 1)
    return SESSION_STORE.list_session_summaries(
        scope=scope,
        limit=effective_limit,
        include_demos=include_demos,
        session_ids=session_ids,
    )


class ClearSessionsRequest(BaseModel):
    confirm: str
    include_demos: bool = False


@app.delete("/api/sessions/{session_ref}")
def delete_session(session_ref: str, include_demo: bool = Query(False)):
    try:
        return SESSION_STORE.delete_session(session_ref, allow_demo=include_demo)
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(403, str(exc))


@app.post("/api/sessions/clear")
def clear_sessions(req: ClearSessionsRequest):
    if req.confirm != "clear-sessions":
        raise HTTPException(400, "confirm must be exactly 'clear-sessions'")
    return SESSION_STORE.clear_sessions(include_demos=req.include_demos)


@app.get("/api/sessions/{session_ref}")
def get_session(session_ref: str):
    s = _resolve_session_ref(session_ref)
    return {
        "session_id": s.session_id,
        "short_name": s.metadata.get("short_name"),
        "caller_arn": s.caller_arn,
        "metadata": s.metadata,
        "denials": [d.__dict__ for d in s.denial_log.records],
    }


@app.get("/api/sessions/{session_ref}/graph")
def get_graph(session_ref: str, request: Request, detail: str = "full"):
    from samoyed.api.auth import verify_api_token

    session = _resolve_session_ref(session_ref)
    allow_restricted = verify_api_token(request.headers.get("Authorization"))
    try:
        return SESSION_STORE.graph_payload(
            session.session_id,
            detail=detail,
            allow_restricted=allow_restricted,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")


class PathQueryRequest(BaseModel):
    start: str | None = "caller"
    target_concept: str | None = None
    target_resource_type: str | None = None
    end_node_id: str | None = None
    end_id_contains: str | None = None
    rel_types: list[str] | None = None
    max_depth: int = 6
    max_paths: int = 20
    mode: str = "paths"  # paths | blast | neighbors
    exclude_node_ids: list[str] | None = None


class GraphQueryRequest(BaseModel):
    start: str | None = "caller"
    mode: str = "paths"
    target_concept: str | None = None
    target_resource_type: str | None = None
    end_node_id: str | None = None
    end_id_contains: str | None = None
    rel_types: list[str] | None = None
    max_depth: int = 6
    max_paths: int = 20
    exclude_node_ids: list[str] | None = None


class NodePropertiesRequest(BaseModel):
    node_id: str
    properties: dict[str, Any]


class MarkNodesRequest(BaseModel):
    refs: list[str]
    compromised: bool | None = None
    high_value: bool | None = None
    mechanism: str | None = None
    source: str = "analyst"
    clear: bool = False


class MarkAlertRequest(BaseModel):
    compromised: list[str] = []
    high_value: list[str] = []
    source: str = "alert"


class MarkingPathsRequest(BaseModel):
    kind: str  # compromised_to_high_value | blast_compromised | to_high_value
    max_depth: int = 6
    max_paths: int = 30
    exclude_node_ids: list[str] | None = None


class DeclareRelationshipRequest(BaseModel):
    relationship: str = "depends_on"
    from_ref: str | None = None
    to_ref: str | None = None
    supplier: str | None = None
    consumer: str | None = None
    dependent: str | None = None
    dependency: str | None = None
    compromise_flow: str = "downstream"
    source: str = "analyst"
    notes: str = ""
    propagate: bool = True


class ProposedChangeRequest(BaseModel):
    type: str
    principal: str | None = None
    target: str | None = None
    action: str | None = None
    rel: str | None = None
    properties: dict[str, Any] = {}


class ChangeAnalyzeRequest(BaseModel):
    changes: list[ProposedChangeRequest]
    context_principal: str | None = "caller"
    max_depth: int = 8


class GraphCompareRequest(BaseModel):
    baseline_ref: str
    proposed_ref: str
    context_principal: str | None = "caller"
    max_depth: int = 10
    max_paths: int = 40


class SessionGraphRoleRequest(BaseModel):
    graph_role: str | None = None
    graph_access: str | None = None


class PolicyAccessRequest(BaseModel):
    principal: str = "caller"
    target: str
    action: str | None = None


@app.get("/api/sessions/{session_ref}/nodes")
def search_nodes(session_ref: str, q: str = "", concept_type: str | None = None, limit: int = 50):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.search_nodes(session.session_id, q=q, concept_type=concept_type, limit=limit)
    except KeyError:
        raise HTTPException(404, "Session not found")


@app.get("/api/enrichment/catalog")
def enrichment_catalog():
    from samoyed.enrichment.catalog import export_catalog

    return export_catalog()


@app.get("/api/enrichment/library")
def enrichment_library():
    """List collector reports in the local enrichment library directory."""
    from samoyed.enrichment.library import default_enrichment_dir, list_enrichment_library

    return {
        "directory": str(default_enrichment_dir()),
        "files": list_enrichment_library(),
    }


@app.get("/api/enrichment/examples")
def enrichment_examples():
    from samoyed.fixtures.enrichment_registry import list_enrichment_examples

    return list_enrichment_examples()


@app.post("/api/sessions/{session_ref}/enrichment/library/{filename}")
def apply_enrichment_library_file(
    session_ref: str,
    filename: str,
    target_node_id: str | None = Query(None),
):
    """Apply an enrichment JSON from ~/.samoyed/enrichments by filename."""
    from samoyed.enrichment.library import read_enrichment_library_file

    session = _resolve_session_ref(session_ref)
    try:
        payload = read_enrichment_library_file(filename)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except FileNotFoundError:
        raise HTTPException(404, f"Enrichment file not found: {filename}")
    try:
        stats = SESSION_STORE.apply_enrichment(
            session.session_id,
            payload,
            target_node_id=target_node_id or None,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    if stats.get("unresolved_bindings") and not stats.get("materials_applied") and not stats.get("unlocks_applied"):
        raise HTTPException(
            400,
            {
                "error": "Enrichment import matched no graph nodes",
                "hint": "Enum/import a session first, or pass target_node_id to force a host",
                "filename": filename,
                "stats": stats,
            },
        )
    return {
        "session_id": session.session_id,
        "filename": filename,
        "stats": stats,
        "target_node_id": target_node_id,
    }


@app.post("/api/sessions/{session_ref}/enrichment/examples/{example_id}")
def apply_enrichment_example(
    session_ref: str,
    example_id: str,
    target_node_id: str | None = Query(None),
):
    from samoyed.fixtures.enrichment_registry import get_enrichment_example, read_enrichment_example_bytes

    session = _resolve_session_ref(session_ref)
    try:
        spec = get_enrichment_example(example_id)
        payload = read_enrichment_example_bytes(example_id)
    except KeyError:
        raise HTTPException(404, f"Unknown enrichment example: {example_id}")
    except FileNotFoundError as exc:
        raise HTTPException(500, str(exc))
    try:
        stats = SESSION_STORE.apply_enrichment(
            session.session_id,
            payload,
            target_node_id=target_node_id or None,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if stats.get("unresolved_bindings") and not stats.get("materials_applied") and not stats.get("unlocks_applied"):
        raise HTTPException(
            400,
            {
                "error": "Enrichment import matched no graph nodes",
                "hint": "Enum/import a session first, or pass target_node_id to force a host",
                "lab_fixture": spec.lab_fixture,
                "stats": stats,
            },
        )
    return {
        "session_id": session.session_id,
        "example_id": example_id,
        "lab_fixture": spec.lab_fixture,
        "stats": stats,
        "target_node_id": target_node_id,
    }


@app.post("/api/sessions/{session_ref}/enrichment")
async def apply_session_enrichment(
    session_ref: str,
    file: UploadFile = File(...),
    target_node_id: str | None = Form(None),
):
    session = _resolve_session_ref(session_ref)
    payload = await file.read()
    if not payload:
        raise HTTPException(400, "Empty file")
    try:
        stats = SESSION_STORE.apply_enrichment(
            session.session_id,
            payload,
            target_node_id=target_node_id or None,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")

    return {
        "session_id": session.session_id,
        "stats": stats,
        "target_node_id": target_node_id,
    }


@app.post("/api/sessions/{session_ref}/enrich-surface")
def enrich_session_surface(session_ref: str):
    """Re-run attack-surface enrichment on the whole session (globs, FEEDS, repairs)."""
    session = _resolve_session_ref(session_ref)
    try:
        stats = SESSION_STORE.enrich_session_surface(session.session_id)
    except KeyError:
        raise HTTPException(404, "Session not found")
    return {"session_id": session.session_id, "stats": stats}


@app.patch("/api/sessions/{session_ref}/nodes")
def patch_node_properties(session_ref: str, req: NodePropertiesRequest):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.update_node_properties(session.session_id, req.node_id, req.properties)
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@app.get("/api/sessions/{session_ref}/markings")
def get_markings(session_ref: str):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.list_markings(session.session_id)
    except KeyError:
        raise HTTPException(404, "Session not found")


@app.get("/api/sessions/{session_ref}/resources/{node_id}/consumers")
def get_resource_consumers(session_ref: str, node_id: str):
    """List producers/consumers of a store — shared-env / poison blast helper."""
    from urllib.parse import unquote

    from samoyed.attack.shared_env import list_resource_consumers

    session = _resolve_session_ref(session_ref)
    resolved = unquote(node_id)
    try:
        ids, _unresolved = SESSION_STORE.resolve_node_refs(session.session_id, [resolved])
        target = ids[0] if ids else resolved
    except Exception:
        target = resolved
    result = list_resource_consumers(session.snapshot, target)
    if result.get("error"):
        raise HTTPException(404, "Resource not found")
    return result


@app.post("/api/sessions/{session_ref}/markings")
def post_markings(session_ref: str, req: MarkNodesRequest):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.mark_nodes(
            session.session_id,
            req.refs,
            compromised=req.compromised,
            high_value=req.high_value,
            mechanism=req.mechanism,
            source=req.source,
            clear=req.clear,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/sessions/{session_ref}/markings/alert")
def post_markings_from_alert(session_ref: str, req: MarkAlertRequest):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.mark_from_alert(
            session.session_id,
            compromised_refs=req.compromised or None,
            high_value_refs=req.high_value or None,
            source=req.source,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/sessions/{session_ref}/paths/markings-query")
def query_marking_paths(session_ref: str, req: MarkingPathsRequest):
    from samoyed.path_engine.format import format_path_query_response

    try:
        session = _resolve_session_ref(session_ref)
        session_id = session.session_id
        result = SESSION_STORE.run_marking_paths_query(
            session_id,
            kind=req.kind,
            max_depth=req.max_depth,
            max_paths=req.max_paths,
            exclude_node_ids=req.exclude_node_ids,
        )
        start = result["compromised_starts"][0] if result["compromised_starts"] else None
        if not start:
            start = SESSION_STORE.find_caller_node(session) or ""
        mode = "blast" if req.kind == "blast_compromised" else "paths"
        formatted = format_path_query_response(
            session_id=session_id,
            graph=session.snapshot,
            start_node_id=start,
            mode=mode,
            raw={"paths": result["paths"]},
            query=req.model_dump(exclude_none=True),
        )
        formatted["kind"] = req.kind
        formatted["markings"] = result["markings"]
        formatted["compromised_starts"] = result["compromised_starts"]
        formatted["high_value_targets"] = result["high_value_targets"]
        return formatted
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/sessions/{session_ref}/relationships")
def post_relationship(session_ref: str, req: DeclareRelationshipRequest):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.declare_relationship(
            session.session_id,
            relationship=req.relationship,
            from_ref=req.from_ref,
            to_ref=req.to_ref,
            supplier=req.supplier,
            consumer=req.consumer,
            dependent=req.dependent,
            dependency=req.dependency,
            compromise_flow=req.compromise_flow,
            source=req.source,
            notes=req.notes,
            propagate=req.propagate,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/sessions/{session_ref}/relationships")
def get_relationships(session_ref: str):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.list_relationships(session.session_id)
    except KeyError:
        raise HTTPException(404, "Session not found")


@app.post("/api/sessions/{session_ref}/relationships/propagate")
def post_propagate_compromise(session_ref: str):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.propagate_compromise(session.session_id)
    except KeyError:
        raise HTTPException(404, "Session not found")


@app.post("/api/sessions/compare")
def compare_sessions(req: GraphCompareRequest):
    try:
        return SESSION_STORE.compare_sessions(
            req.baseline_ref,
            req.proposed_ref,
            context_principal=req.context_principal,
            max_depth=req.max_depth,
            max_paths=req.max_paths,
        )
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.patch("/api/sessions/{session_ref}/graph-role")
def patch_session_graph_role(session_ref: str, req: SessionGraphRoleRequest):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.set_session_graph_role(
            session.session_id,
            graph_role=req.graph_role,
            graph_access=req.graph_access,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")


@app.post("/api/sessions/{session_ref}/changes/analyze")
def analyze_proposed_changes(session_ref: str, req: ChangeAnalyzeRequest):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.analyze_proposed_changes(
            session.session_id,
            [c.model_dump(exclude_none=True) for c in req.changes],
            context_principal=req.context_principal,
            max_depth=req.max_depth,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/sessions/{session_ref}/policy/access-check")
def policy_access_check(session_ref: str, req: PolicyAccessRequest):
    session = _resolve_session_ref(session_ref)
    try:
        return SESSION_STORE.check_policy_access(
            session.session_id,
            principal=req.principal,
            target=req.target,
            action=req.action,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/sessions/{session_ref}/search-suggestions")
def get_search_suggestions(session_ref: str, limit: int = 10):
    session = _resolve_session_ref(session_ref)
    return suggest_searches(SESSION_STORE, session.session_id, limit=limit)


@app.post("/api/sessions/{session_ref}/paths/query")
def query_paths_post(session_ref: str, req: PathQueryRequest):
    return _run_session_graph_query(session_ref, req)


@app.post("/api/sessions/{session_ref}/graph/query")
def graph_query_post(session_ref: str, req: GraphQueryRequest):
    return _run_session_graph_query(session_ref, req)


def _run_session_graph_query(
    session_ref: str,
    req: PathQueryRequest | GraphQueryRequest,
    *,
    graph_query: bool = False,
):
    from samoyed.path_engine.format import format_path_query_response

    try:
        session = _resolve_session_ref(session_ref)
        session_id = session.session_id
        start = SESSION_STORE.resolve_start_node(session_id, req.start)
        if not start:
            raise HTTPException(400, "Start node not found")
        end_node_id = req.end_node_id
        if end_node_id:
            end_node_id = SESSION_STORE.resolve_end_node(session_id, end_node_id) or end_node_id
        result = SESSION_STORE.run_graph_query(
            session_id,
            start_node_id=start,
            mode=req.mode,
            target_concept=req.target_concept,
            target_resource_type=req.target_resource_type,
            end_node_id=end_node_id,
            end_id_contains=req.end_id_contains,
            rel_types=req.rel_types,
            max_depth=req.max_depth,
            max_paths=req.max_paths,
            exclude_node_ids=getattr(req, "exclude_node_ids", None),
        )
        if req.mode == "neighbors" and result.get("nodes"):
            paths = [
                {
                    "path_id": f"neighbor-{i}",
                    "score": 0.5,
                    "node_ids": [start, n["node_id"]],
                    "target_match": {
                        "node_id": n["node_id"],
                        "concept_type": n["props"].get("concept_type"),
                        "resource_type": n["props"].get("resource_type"),
                    },
                    "steps": [
                        {
                            "step": 0,
                            "src": start,
                            "rel": n["rel_type"],
                            "dst": n["node_id"],
                        }
                    ],
                }
                for i, n in enumerate(result["nodes"])
            ]
            result = {**result, "paths": paths}

        query_payload = req.model_dump(exclude_none=True)
        return format_path_query_response(
            session_id=session_id,
            graph=session.snapshot,
            start_node_id=start,
            mode=req.mode,
            raw=result,
            query=query_payload,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/sessions/{session_ref}/paths/blast")
def blast_paths_get(
    session_ref: str,
    start: str = Query("caller"),
    max_depth: int = Query(6, ge=1, le=12),
    max_paths: int = Query(20, ge=1, le=50),
):
    """GET-friendly blast radius for curl | jq (defender IR scripts)."""
    req = PathQueryRequest(start=start, mode="blast", max_depth=max_depth, max_paths=max_paths)
    return _run_session_graph_query(session_ref, req)


@app.get("/api/paths/blast")
def blast_paths_default(
    session: str | None = Query(None, description="Session id or short name; defaults to most recent"),
    start: str = Query("caller"),
    max_depth: int = Query(6, ge=1, le=12),
    max_paths: int = Query(20, ge=1, le=50),
):
    """Blast radius without session id in the path — session ref is optional."""
    req = PathQueryRequest(start=start, mode="blast", max_depth=max_depth, max_paths=max_paths)
    return _run_session_graph_query(session, req)


@app.get("/api/paths")
def query_paths(
    session: str | None = Query(None, alias="session_id"),
    start: str | None = None,
    target_concept: str | None = None,
    target_resource_type: str | None = None,
    max_depth: int = 6,
):
    session_record = _resolve_session_ref(session)
    try:
        paths = SESSION_STORE.query_paths(
            session_record.session_id,
            start_node_id=start,
            target_concept=target_concept,
            target_resource_type=target_resource_type,
            max_depth=max_depth,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    return [_serialize_path(p) for p in paths]


@app.post("/api/scenarios/{name}/run")
def run_scenario(
    name: str,
    session_id: str | None = Query(None, description="Session id or short name; defaults to most recent"),
    start: str | None = Query(None),
):
    from samoyed.path_engine.format import format_path_query_response

    try:
        session = _resolve_session_ref(session_id)
        session_id = session.session_id
        start_node = SESSION_STORE.resolve_start_node(session_id, start) if start else None
        if start_node:
            paths = SESSION_STORE.run_scenario(session_id, name, start_node_id=start_node)
        else:
            paths = SESSION_STORE.run_scenario(session_id, name)
            start_node = SESSION_STORE.find_caller_node(session) or ""
        serialized = [_serialize_path(p) for p in paths]
        return format_path_query_response(
            session_id=session_id,
            graph=session.snapshot,
            start_node_id=start_node,
            mode="blast" if name == "leaked-credential" else name,
            raw={"paths": serialized},
            query={"scenario": name, "start": start},
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/ontology")
def ontology():
    return export_ontology()


@app.get("/api/fixtures")
def list_fixtures():
    from samoyed.fixtures.registry import list_fixtures

    return list_fixtures(demo_only=True)


@app.post("/api/sessions/fixtures/{fixture_id}")
def import_fixture_session(fixture_id: str):
    try:
        record = SESSION_STORE.load_fixture(fixture_id)
    except KeyError:
        raise HTTPException(404, f"Unknown fixture: {fixture_id}")
    except FileNotFoundError as exc:
        raise HTTPException(500, str(exc))
    return {
        "session_id": record.session_id,
        "short_name": record.metadata.get("short_name"),
        "caller_arn": record.caller_arn,
        "fixture_id": record.metadata.get("fixture_id"),
        "metadata": record.metadata,
    }


def _serialize_path(p):
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


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/login")
    def login_page():
        return FileResponse(STATIC_DIR / "login.html")

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")
