from samoyed.api.search_suggestions import _has_gcp
from samoyed.cloud.concepts import CloudProvider
from samoyed.graph.model import GraphNode, GraphSnapshot
from samoyed.sessions import SessionRecord


def _session(nodes, metadata=None):
    return SessionRecord(
        session_id="test",
        provider=CloudProvider.AWS,
        caller_arn="",
        scope_id="",
        created_at="",
        status="complete",
        snapshot=GraphSnapshot("test", nodes=nodes),
        metadata=metadata or {},
    )


def test_gcp_detection_includes_gcp_resource_prefixes():
    session = _session({"bucket": GraphNode("bucket", "DataStore", {"native_id": "GCSBucket:demo"})})
    assert _has_gcp(session)


def test_gcp_detection_includes_network_inventory_provider():
    assert _has_gcp(_session({}, {"network_inventory": {"provider": "gcp"}}))
