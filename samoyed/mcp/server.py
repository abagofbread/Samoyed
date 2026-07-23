from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from samoyed.cloud.ontology import export_ontology
from samoyed.path_engine.format import format_path_query_response
from samoyed.sessions import SESSION_STORE

mcp = FastMCP("samoyed")


def _resolve_session(session_ref: str | None):
    session = SESSION_STORE.resolve_session_ref(session_ref)
    if not session:
        return None
    return session


def _path(p) -> dict:
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


@mcp.tool()
def list_sessions() -> str:
    """List enumeration sessions (id, short_name, caller, node count)."""
    summaries = SESSION_STORE.list_session_summaries(scope="all", limit=500, include_demos=True)
    return json.dumps(
        [
            {
                "session_id": s["session_id"],
                "short_name": s.get("short_name"),
                "caller_arn": s.get("caller_arn"),
                "created_at": s.get("created_at"),
                "node_count": (s.get("metadata") or {}).get("node_count", 0),
            }
            for s in summaries
        ],
        indent=2,
    )


@mcp.tool()
def get_session_summary(session_id: str | None = None) -> str:
    """Session stats; session_id optional (uses most recent non-demo session)."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    markings = SESSION_STORE.list_markings(session.session_id)
    return json.dumps(
        {
            "session_id": session.session_id,
            "short_name": session.metadata.get("short_name"),
            "caller_arn": session.caller_arn,
            "metadata": session.metadata,
            "denial_count": len(session.denial_log.records),
            "denials": [d.__dict__ for d in session.denial_log.records[:20]],
            "markings": {
                "compromised_count": markings["compromised_count"],
                "high_value_count": markings["high_value_count"],
            },
        },
        indent=2,
        default=str,
    )


@mcp.tool()
def list_markings(session_id: str | None = None) -> str:
    """List nodes marked compromised or high-value in a session."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    try:
        return json.dumps(SESSION_STORE.list_markings(session.session_id), indent=2, default=str)
    except KeyError:
        return json.dumps({"error": "session not found"})


@mcp.tool()
def mark_nodes(
    refs_json: str,
    session_id: str | None = None,
    compromised: bool | None = None,
    high_value: bool | None = None,
    mechanism: str | None = None,
    source: str = "mcp",
    clear: bool = False,
) -> str:
    """
    Mark graph nodes as compromised and/or high-value (crown jewels).

    refs_json: JSON array of node ids, ARNs, display names, or aliases.
    Examples: '["arn:aws:iam::123:user/jane"]', '["prod-db", "caller"]'
    Use compromised=true for IR start nodes, high_value=true for targets.
    Optional mechanism (ssrf, ci-runner, static-poison, leaked-key, …) labels
    *how* compromise is hypothesized — does not invent CVE inventory.
    """
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    try:
        refs = json.loads(refs_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "refs_json must be a JSON array of strings"})
    if not isinstance(refs, list):
        return json.dumps({"error": "refs_json must be a JSON array"})
    try:
        result = SESSION_STORE.mark_nodes(
            session.session_id,
            [str(r) for r in refs],
            compromised=compromised,
            high_value=high_value,
            mechanism=mechanism,
            source=source,
            clear=clear,
        )
    except KeyError:
        return json.dumps({"error": "session not found"})
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def mark_from_alert(alert_json: str, session_id: str | None = None, source: str = "alert") -> str:
    """
    Bulk-mark compromised principals and crown jewels from an alert/ticket payload.

    alert_json example:
    {"compromised": ["arn:aws:iam::123:user/jane"], "high_value": ["prod-db", "corp-vault"]}
    """
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    try:
        payload = json.loads(alert_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "alert_json must be valid JSON"})
    if not isinstance(payload, dict):
        return json.dumps({"error": "alert_json must be an object"})
    try:
        result = SESSION_STORE.mark_from_alert(
            session.session_id,
            compromised_refs=payload.get("compromised") or None,
            high_value_refs=payload.get("high_value") or None,
            source=source,
        )
    except KeyError:
        return json.dumps({"error": "session not found"})
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def declare_relationship(
    relationship: str = "depends_on",
    session_id: str | None = None,
    dependent: str | None = None,
    dependency: str | None = None,
    from_ref: str | None = None,
    to_ref: str | None = None,
    notes: str = "",
    compromise_flow: str = "downstream",
    propagate: bool = True,
    source: str = "mcp",
) -> str:
    """
    Declare a controlling dependency: dependent --DEPENDS_ON--> dependency.

    Compromise on the dependency (control point) flows to the dependent by default.

    CI/CD supply-chain example:
      declare_relationship(dependent="build-pipeline", dependency="artifact-bucket")
      declare_relationship(dependent="prod-workloads", dependency="build-pipeline")
    After marking the leaked principal compromised, WRITES taints the bucket and
    DEPENDS_ON chains to pipeline and prod.
    """
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    try:
        result = SESSION_STORE.declare_relationship(
            session.session_id,
            relationship=relationship,
            dependent=dependent,
            dependency=dependency,
            from_ref=from_ref,
            to_ref=to_ref,
            notes=notes,
            compromise_flow=compromise_flow,
            propagate=propagate,
            source=source,
        )
    except KeyError:
        return json.dumps({"error": "session not found"})
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def list_relationships(session_id: str | None = None) -> str:
    """List analyst-declared dependency/supply-chain edges in a session."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    try:
        return json.dumps(SESSION_STORE.list_relationships(session.session_id), indent=2, default=str)
    except KeyError:
        return json.dumps({"error": "session not found"})


@mcp.tool()
def propagate_compromise_markings(session_id: str | None = None) -> str:
    """Re-run compromise propagation along WRITES and DEPENDS_ON edges."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    try:
        return json.dumps(SESSION_STORE.propagate_compromise(session.session_id), indent=2, default=str)
    except KeyError:
        return json.dumps({"error": "session not found"})


@mcp.tool()
def find_attack_paths(
    target_concept: str = "SecretStore",
    session_id: str | None = None,
    start_node_id: str | None = None,
    max_depth: int = 6,
) -> str:
    """Find ranked attack paths. start_node_id can be ARN, node id, caller, or compromised."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    sid = session.session_id
    start = SESSION_STORE.resolve_start_node(sid, start_node_id) if start_node_id else None
    try:
        paths = SESSION_STORE.query_paths(
            sid,
            start_node_id=start,
            target_concept=target_concept,
            max_depth=max_depth,
        )
    except KeyError:
        return json.dumps({"error": "session not found"})
    return json.dumps([_path(p) for p in paths], indent=2)


@mcp.tool()
def get_blast_radius(session_id: str | None = None, start_node_id: str | None = None) -> str:
    """Blast radius from compromised start (caller, ARN, or compromised alias)."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    sid = session.session_id
    start = SESSION_STORE.resolve_start_node(sid, start_node_id) if start_node_id else None
    try:
        paths = SESSION_STORE.blast_radius(sid, start)
    except KeyError:
        return json.dumps({"error": "session not found"})
    payload = format_path_query_response(
        session_id=sid,
        graph=session.snapshot,
        start_node_id=start or SESSION_STORE.find_caller_node(session) or "",
        mode="blast",
        raw={"paths": [_path(p) for p in paths]},
        query={"start": start_node_id},
    )
    return json.dumps(payload, indent=2, default=str)


@mcp.tool()
def search_nodes(
    session_id: str | None = None,
    concept_type: str | None = None,
    resource_type: str | None = None,
    native_id_contains: str | None = None,
) -> str:
    """Search graph nodes by concept type, resource type, or native ID substring."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    results = []
    for node in session.snapshot.nodes.values():
        if concept_type and node.props.get("concept_type") != concept_type:
            continue
        if resource_type and node.props.get("resource_type") != resource_type:
            continue
        nid = node.props.get("native_id", node.node_id)
        if native_id_contains and native_id_contains not in str(nid):
            continue
        results.append({"id": node.node_id, "label": node.label, **node.props})
    return json.dumps(results[:100], indent=2, default=str)


@mcp.tool()
def get_neighbors(
    node_id: str,
    session_id: str | None = None,
    rel_type: str | None = None,
    direction: str = "out",
) -> str:
    """List adjacent nodes for a graph node (in, out, or both directions)."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    try:
        neighbors = SESSION_STORE.get_neighbors(
            session.session_id, node_id, rel_type=rel_type, direction=direction
        )
    except KeyError:
        return json.dumps({"error": "session not found"})
    return json.dumps(neighbors, indent=2, default=str)


@mcp.tool()
def explain_path(path_id: str, session_id: str | None = None) -> str:
    """Explain an attack path with human-readable hop narratives."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    try:
        explanation = SESSION_STORE.explain_path(session.session_id, path_id)
    except KeyError:
        return json.dumps({"error": "session not found"})
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps(explanation, indent=2, default=str)


@mcp.tool()
def run_cypher(query: str, params_json: str = "{}") -> str:
    """Run a read-only Cypher query against Neo4j (requires NEO4J_URI)."""
    from samoyed.graph.neo4j_store import run_readonly_cypher

    try:
        params = json.loads(params_json) if params_json else {}
        rows = run_readonly_cypher(query, params=params)
    except (RuntimeError, ValueError) as exc:
        return json.dumps({"error": str(exc)})
    except json.JSONDecodeError:
        return json.dumps({"error": "params_json must be valid JSON"})
    return json.dumps(rows, indent=2, default=str)


@mcp.tool()
def run_scenario(
    scenario_name: str = "leaked-credential",
    session_id: str | None = None,
    start_node_id: str | None = None,
) -> str:
    """Run a blast-radius scenario. start_node_id optional (ARN, caller, compromised)."""
    session = _resolve_session(session_id)
    if not session:
        return json.dumps({"error": "session not found"})
    sid = session.session_id
    start = SESSION_STORE.resolve_start_node(sid, start_node_id) if start_node_id else None
    try:
        paths = SESSION_STORE.run_scenario(sid, scenario_name, start_node_id=start)
    except KeyError:
        return json.dumps({"error": "session not found"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    start_resolved = start or SESSION_STORE.find_caller_node(session) or ""
    payload = format_path_query_response(
        session_id=sid,
        graph=session.snapshot,
        start_node_id=start_resolved,
        mode="blast" if scenario_name == "leaked-credential" else scenario_name,
        raw={"paths": [_path(p) for p in paths]},
        query={"scenario": scenario_name, "start": start_node_id},
    )
    return json.dumps(payload, indent=2, default=str)


@mcp.resource("samoyed://ontology")
def ontology_resource() -> str:
    """Cloud/orchestration concept taxonomy."""
    return json.dumps(export_ontology(), indent=2)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
