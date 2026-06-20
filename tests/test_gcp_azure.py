from __future__ import annotations

from samoyed.cloud.capabilities import map_azure_role, map_gcp_role
from samoyed.graph.sample_azure import build_sample_azure_graph
from samoyed.graph.sample_gcp import build_sample_gcp_graph
from samoyed.path_engine.search import find_attack_paths
from samoyed.scenarios.leaked_credential import LeakedCredentialScenario


def test_map_gcp_role_secret_accessor():
    m = map_gcp_role("roles/secretmanager.secretAccessor")
    assert m is not None
    assert m.capability.value == "READS"


def test_map_azure_role_keyvault():
    m = map_azure_role("Key Vault Secrets User")
    assert m is not None
    assert m.capability.value == "READS"


def test_sample_gcp_paths():
    snapshot = build_sample_gcp_graph("gcp-path-test")
    caller = next(n for n in snapshot.nodes.values() if n.props.get("is_caller"))
    paths = LeakedCredentialScenario().run(snapshot, caller.node_id)
    assert len(paths) >= 1
    secret_paths = find_attack_paths(
        snapshot, start_node_id=caller.node_id, target_concept="SecretStore", max_depth=4
    )
    assert len(secret_paths) >= 1


def test_sample_azure_paths():
    snapshot = build_sample_azure_graph("azure-path-test")
    caller = next(n for n in snapshot.nodes.values() if n.props.get("is_caller"))
    paths = LeakedCredentialScenario().run(snapshot, caller.node_id)
    assert len(paths) >= 1
