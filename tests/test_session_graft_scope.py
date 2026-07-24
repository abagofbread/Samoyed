from __future__ import annotations

from types import SimpleNamespace

from samoyed.graph.builder import GraphBuilder, stable_id
from samoyed.network.session_graft import ensure_scope_boundary, find_session_for_scope


def test_gcp_project_scope_session_lookup_and_boundary():
    scope_id = "gcp:project:proj-pci"
    session = SimpleNamespace(
        session_id="pci-session",
        scope_id=scope_id,
        provider="gcp",
        metadata={"project_id": "proj-pci"},
        snapshot=GraphBuilder("pci-session").snapshot,
    )
    store = SimpleNamespace(list_sessions=lambda: [session])

    assert find_session_for_scope(store, scope_id) is session

    builder = GraphBuilder("current")
    node_id = ensure_scope_boundary(builder, scope_id)
    assert node_id == stable_id("ScopeBoundary", scope_id)
    assert builder.snapshot.nodes[node_id].props["project_id"] == "proj-pci"
    assert builder.snapshot.nodes[node_id].props["boundary_kind"] == "project"
