from __future__ import annotations

from samoyed.cloud.ontology import export_ontology
from samoyed.cloud.providers import make_scope_id, parse_scope_id
from samoyed.cloud.concepts import CloudProvider
from samoyed.graph.sample import build_sample_graph
from samoyed.path_engine.search import find_attack_paths
from samoyed.scenarios.leaked_credential import LeakedCredentialScenario


def test_export_ontology_has_mappings():
    data = export_ontology()
    assert "concept_mappings" in data
    assert len(data["concept_mappings"]) >= 10
    assert "SecretStore" in data["concepts"]
    assert "CAN_PRIVESC_TO" in data["traversable_relationships"]


def test_scope_id_roundtrip():
    sid = make_scope_id(CloudProvider.AWS, "account", "123456789012")
    provider, kind, ident = parse_scope_id(sid)
    assert provider == CloudProvider.AWS
    assert kind == "account"
    assert ident == "123456789012"


def test_sample_graph_scenario():
    snapshot = build_sample_graph("test-sample")
    caller = next(n for n in snapshot.nodes.values() if n.props.get("is_caller"))
    paths = LeakedCredentialScenario().run(snapshot, caller.node_id)
    assert len(paths) >= 1
    secret_paths = find_attack_paths(
        snapshot, start_node_id=caller.node_id, target_concept="SecretStore", max_depth=4
    )
    assert len(secret_paths) == 1
