from __future__ import annotations

from samoyed.graph.enrichment import (
    ENRICHMENT_EDGE_ORIGIN,
    is_enrichment_edge,
    mark_enrichment_edges,
)
from samoyed.graph.model import GraphEdge, GraphSnapshot


def test_is_enrichment_edge_detects_pivot_rels():
    assert is_enrichment_edge("STORES_CREDS_FOR", {"confidence": "explicit"})
    assert is_enrichment_edge("CAN_ESCAPE_TO", {"mechanism": "imds", "source": "surface-enrichment"})
    assert not is_enrichment_edge("READS", {"role": "s3:GetObject"})
    assert not is_enrichment_edge("EXECUTES_AS", {"execution_role_arn": "arn:aws:iam::1:role/x"})


def test_mark_enrichment_edges_tags_snapshot():
    snap = GraphSnapshot(session_id="t")
    snap.add_edge(
        GraphEdge(
            src_id="a",
            rel_type="CAN_ESCAPE_TO",
            dst_id="b",
            props={"mechanism": "imds", "source": "surface-enrichment"},
        )
    )
    assert mark_enrichment_edges(snap) == 1
    assert snap.edges[0].props["edge_origin"] == ENRICHMENT_EDGE_ORIGIN
    assert mark_enrichment_edges(snap) == 0
