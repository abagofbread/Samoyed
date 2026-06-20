from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from samoyed.cloud.ontology import export_ontology
from samoyed.sessions import SESSION_STORE

mcp = FastMCP("samoyed")


@mcp.tool()
def list_sessions() -> str:
    """List all enumeration sessions."""
    sessions = SESSION_STORE.list_sessions()
    return json.dumps(
        [
            {
                "session_id": s.session_id,
                "caller_arn": s.caller_arn,
                "created_at": s.created_at,
                "node_count": s.metadata.get("node_count", 0),
            }
            for s in sessions
        ],
        indent=2,
    )


@mcp.tool()
def get_session_summary(session_id: str) -> str:
    """Get summary stats for an enumeration session."""
    s = SESSION_STORE.get(session_id)
    if not s:
        return json.dumps({"error": "session not found"})
    return json.dumps(
        {
            "session_id": s.session_id,
            "caller_arn": s.caller_arn,
            "metadata": s.metadata,
            "denial_count": len(s.denial_log.records),
            "denials": [d.__dict__ for d in s.denial_log.records[:20]],
        },
        indent=2,
        default=str,
    )


@mcp.tool()
def find_attack_paths(
    session_id: str,
    start_node_id: str | None = None,
    target_concept: str = "SecretStore",
    max_depth: int = 6,
) -> str:
    """Find ranked attack paths from a start node to a target concept."""
    try:
        paths = SESSION_STORE.query_paths(
            session_id,
            start_node_id=start_node_id,
            target_concept=target_concept,
            max_depth=max_depth,
        )
    except KeyError:
        return json.dumps({"error": "session not found"})
    return json.dumps([_path(p) for p in paths], indent=2)


@mcp.tool()
def get_blast_radius(session_id: str, start_node_id: str | None = None) -> str:
    """Get all high-value reachable targets from a compromised identity."""
    try:
        paths = SESSION_STORE.blast_radius(session_id, start_node_id)
    except KeyError:
        return json.dumps({"error": "session not found"})
    return json.dumps([_path(p) for p in paths], indent=2)


@mcp.tool()
def search_nodes(
    session_id: str,
    concept_type: str | None = None,
    resource_type: str | None = None,
    native_id_contains: str | None = None,
) -> str:
    """Search graph nodes by concept type, resource type, or native ID substring."""
    s = SESSION_STORE.get(session_id)
    if not s:
        return json.dumps({"error": "session not found"})
    results = []
    for node in s.snapshot.nodes.values():
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
    session_id: str,
    node_id: str,
    rel_type: str | None = None,
    direction: str = "out",
) -> str:
    """List adjacent nodes for a graph node (in, out, or both directions)."""
    try:
        neighbors = SESSION_STORE.get_neighbors(
            session_id, node_id, rel_type=rel_type, direction=direction
        )
    except KeyError:
        return json.dumps({"error": "session not found"})
    return json.dumps(neighbors, indent=2, default=str)


@mcp.tool()
def explain_path(session_id: str, path_id: str) -> str:
    """Explain an attack path with human-readable hop narratives."""
    try:
        explanation = SESSION_STORE.explain_path(session_id, path_id)
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
def run_scenario(session_id: str, scenario_name: str = "leaked-credential") -> str:
    """Run a blast-radius scenario and return ranked paths."""
    try:
        paths = SESSION_STORE.run_scenario(session_id, scenario_name)
    except KeyError:
        return json.dumps({"error": "session not found"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps([_path(p) for p in paths], indent=2)


@mcp.resource("samoyed://ontology")
def ontology_resource() -> str:
    """Cloud/orchestration concept taxonomy."""
    return json.dumps(export_ontology(), indent=2)


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


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
