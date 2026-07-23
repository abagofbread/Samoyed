from __future__ import annotations

from samoyed.graph.model import GraphEdge, GraphNode, GraphSnapshot
from samoyed.graph.repair import repair_legacy_internet_exposure


def test_repairs_recursive_internet_exposure_nodes() -> None:
    graph = GraphSnapshot(session_id="legacy")
    graph.add_node(
        GraphNode(
            node_id="internet",
            label="Resource",
            props={
                "native_id": "network:internet",
                "display_name": "Public internet",
                "resource_type": "NetworkExposure",
            },
        )
    )
    graph.add_node(
        GraphNode(
            node_id="instance",
            label="Resource",
            props={"native_id": "EC2Instance:i-public", "display_name": "public-instance"},
        )
    )
    graph.add_node(
        GraphNode(
            node_id="exposure-1",
            label="Resource",
            props={
                "native_id": "network:exposure:internet:instance",
                "display_name": "internet exposure for public-instance",
                "target_resource": "instance",
                "resource_type": "NetworkExposure",
            },
        )
    )
    graph.add_node(
        GraphNode(
            node_id="exposure-2",
            label="Resource",
            props={
                "native_id": "network:exposure:internet:exposure-1",
                "display_name": "internet exposure for internet exposure for public-instance",
                "target_resource": "exposure-1",
                "resource_type": "NetworkExposure",
            },
        )
    )
    graph.add_node(
        GraphNode(
            node_id="internet-exposure",
            label="Resource",
            props={
                "native_id": "network:exposure:internet:internet",
                "display_name": "internet exposure for Public internet",
                "target_resource": "internet",
                "resource_type": "NetworkExposure",
            },
        )
    )
    graph.add_node(
        GraphNode(
            node_id="internal-exposure",
            label="Resource",
            props={
                "native_id": "network:exposure:internal:instance",
                "display_name": "internal exposure for public-instance",
                "target_resource": "instance",
                "resource_type": "NetworkExposure",
            },
        )
    )
    graph.add_edge(GraphEdge("internet", "CAN_REACH", "exposure-2"))
    graph.add_edge(GraphEdge("exposure-2", "CAN_REACH", "exposure-1"))
    graph.add_edge(GraphEdge("exposure-1", "CAN_REACH", "instance"))
    graph.add_edge(GraphEdge("internet", "CAN_REACH", "internet-exposure"))

    stats = repair_legacy_internet_exposure(graph)

    assert stats == {"removed_nodes": 4, "added_edges": 1}
    assert set(graph.nodes) == {"internet", "instance"}
    assert graph.nodes["internet"].props["display_name"] == "The Internet"
    assert [
        (edge.src_id, edge.rel_type, edge.dst_id)
        for edge in graph.edges
    ] == [("internet", "CAN_REACH", "instance")]

    assert repair_legacy_internet_exposure(graph) == {
        "removed_nodes": 0,
        "added_edges": 0,
    }
