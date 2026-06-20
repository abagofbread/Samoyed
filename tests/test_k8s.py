from __future__ import annotations

from samoyed.enumerators.k8s.escape_surface import analyze_pod_spec
from samoyed.enumerators.k8s.helpers import rule_grants
from samoyed.graph.sample_k8s import build_sample_k8s_graph
from samoyed.path_engine.search import find_attack_paths
from samoyed.scenarios.k8s import CompromisedSaScenario, PodEscapeScenario


def test_analyze_pod_privileged_and_docker_sock():
    spec = {
        "metadata": {"namespace": "default", "name": "evil"},
        "spec": {
            "hostPID": True,
            "containers": [
                {
                    "name": "main",
                    "securityContext": {"privileged": True},
                    "volumeMounts": [{"mountPath": "/var/run/docker.sock"}],
                }
            ],
            "volumes": [{"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}}],
        },
    }
    findings = analyze_pod_spec(spec)
    kinds = {f["kind"] for f in findings}
    assert "privileged" in kinds
    assert "hostPID" in kinds
    assert "hostPath" in kinds or "docker-socket" in kinds


def test_rule_grants_secrets_read():
    rules = [{"verbs": ["get", "list"], "resources": ["secrets"], "apiGroups": [""]}]
    grants = rule_grants(rules)
    assert ("READS", "SecretStore") in grants


def test_rule_grants_cluster_admin():
    rules = [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]
    grants = rule_grants(rules)
    assert ("CAN_ACCESS", "ManagementEndpoint") in grants


def test_sample_k8s_compromised_sa_scenario():
    snapshot = build_sample_k8s_graph("k8s-test")
    caller = next(n for n in snapshot.nodes.values() if n.props.get("is_caller"))
    paths = CompromisedSaScenario().run(snapshot, caller.node_id)
    assert len(paths) >= 1
    secret_paths = find_attack_paths(
        snapshot,
        start_node_id=caller.node_id,
        target_concept="SecretStore",
        max_depth=4,
    )
    assert len(secret_paths) >= 1


def test_sample_k8s_pod_escape_scenario():
    snapshot = build_sample_k8s_graph("k8s-escape-test")
    pod = next(n for n in snapshot.nodes.values() if n.props.get("name") == "evil-pod")
    paths = PodEscapeScenario().run(snapshot, pod.node_id)
    assert len(paths) >= 1
    escape_paths = find_attack_paths(
        snapshot,
        start_node_id=pod.node_id,
        target_concept="EscapeSurface",
        max_depth=3,
    )
    assert len(escape_paths) >= 1
