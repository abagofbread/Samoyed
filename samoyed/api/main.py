from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
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


@app.get("/api/sessions")
def list_sessions():
    return [
        {
            "session_id": s.session_id,
            "caller_arn": s.caller_arn,
            "created_at": s.created_at,
            "metadata": s.metadata,
        }
        for s in SESSION_STORE.list_sessions()
    ]


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str):
    s = SESSION_STORE.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    return {
        "session_id": s.session_id,
        "caller_arn": s.caller_arn,
        "metadata": s.metadata,
        "denials": [d.__dict__ for d in s.denial_log.records],
    }


@app.get("/api/sessions/{session_id}/graph")
def get_graph(session_id: str):
    s = SESSION_STORE.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    return {
        "nodes": [
            {"id": n.node_id, "label": n.label, **n.props} for n in s.snapshot.nodes.values()
        ],
        "edges": [
            {"src": e.src_id, "rel": e.rel_type, "dst": e.dst_id, **e.props}
            for e in s.snapshot.edges
        ],
    }


class PathQueryRequest(BaseModel):
    start: str | None = "caller"
    target_concept: str | None = None
    target_resource_type: str | None = None
    max_depth: int = 6
    mode: str = "paths"  # paths | blast | neighbors


class NodePropertiesRequest(BaseModel):
    node_id: str
    properties: dict[str, Any]


@app.get("/api/sessions/{session_id}/nodes")
def search_nodes(session_id: str, q: str = "", concept_type: str | None = None, limit: int = 50):
    try:
        return SESSION_STORE.search_nodes(session_id, q=q, concept_type=concept_type, limit=limit)
    except KeyError:
        raise HTTPException(404, "Session not found")


@app.patch("/api/sessions/{session_id}/nodes")
def patch_node_properties(session_id: str, req: NodePropertiesRequest):
    try:
        return SESSION_STORE.update_node_properties(session_id, req.node_id, req.properties)
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@app.get("/api/sessions/{session_id}/search-suggestions")
def get_search_suggestions(session_id: str, limit: int = 10):
    if not SESSION_STORE.get(session_id):
        raise HTTPException(404, "Session not found")
    return suggest_searches(SESSION_STORE, session_id, limit=limit)


@app.post("/api/sessions/{session_id}/paths/query")
def query_paths_post(session_id: str, req: PathQueryRequest):
    try:
        start = SESSION_STORE.resolve_start_node(session_id, req.start)
        if not start:
            raise HTTPException(400, "Start node not found")
        if req.mode == "blast":
            paths = SESSION_STORE.blast_radius(
                session_id, start_node_id=start, max_depth=req.max_depth
            )
        elif req.mode == "neighbors":
            neighbors = SESSION_STORE.get_neighbors(session_id, start)
            paths = [
                {
                    "path_id": f"neighbor-{i}",
                    "score": 0.5,
                    "node_ids": [start, n["node_id"]],
                    "target_match": {"node_id": n["node_id"], "concept_type": n["props"].get("concept_type")},
                    "steps": [
                        {
                            "step": 0,
                            "src": start,
                            "rel": n["rel_type"],
                            "dst": n["node_id"],
                        }
                    ],
                }
                for i, n in enumerate(neighbors)
            ]
            return {"start": start, "mode": req.mode, "paths": paths}
        else:
            paths = SESSION_STORE.query_paths(
                session_id,
                start_node_id=start,
                target_concept=req.target_concept,
                target_resource_type=req.target_resource_type,
                max_depth=req.max_depth,
            )
        return {"start": start, "mode": req.mode, "paths": [_serialize_path(p) for p in paths]}
    except KeyError:
        raise HTTPException(404, "Session not found")


@app.get("/api/paths")
def query_paths(
    session_id: str,
    start: str | None = None,
    target_concept: str | None = None,
    target_resource_type: str | None = None,
    max_depth: int = 6,
):
    try:
        paths = SESSION_STORE.query_paths(
            session_id,
            start_node_id=start,
            target_concept=target_concept,
            target_resource_type=target_resource_type,
            max_depth=max_depth,
        )
    except KeyError:
        raise HTTPException(404, "Session not found")
    return [_serialize_path(p) for p in paths]


@app.post("/api/scenarios/{name}/run")
def run_scenario(name: str, session_id: str):
    try:
        paths = SESSION_STORE.run_scenario(session_id, name)
    except KeyError:
        raise HTTPException(404, "Session not found")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"scenario": name, "paths": [_serialize_path(p) for p in paths]}


@app.get("/api/ontology")
def ontology():
    return export_ontology()


@app.post("/api/sessions/sample")
def create_sample_session():
    record = SESSION_STORE.load_sample_session()
    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
        "metadata": record.metadata,
    }


@app.post("/api/sessions/sample-k8s")
def create_sample_k8s_session():
    record = SESSION_STORE.load_sample_k8s_session()
    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
        "metadata": record.metadata,
    }


@app.post("/api/sessions/sample-gcp")
def create_sample_gcp_session():
    record = SESSION_STORE.load_sample_gcp_session()
    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
        "metadata": record.metadata,
    }


@app.post("/api/sessions/sample-azure")
def create_sample_azure_session():
    record = SESSION_STORE.load_sample_azure_session()
    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
        "metadata": record.metadata,
    }


@app.post("/api/sessions/sample-host")
def create_sample_host_session():
    record = SESSION_STORE.load_sample_host_session()
    return {
        "session_id": record.session_id,
        "caller_arn": record.caller_arn,
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
