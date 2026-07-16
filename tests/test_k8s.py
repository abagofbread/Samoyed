from __future__ import annotations

from samoyed.enumerators.k8s.escape_surface import analyze_pod_spec
from samoyed.enumerators.k8s.helpers import rule_grants
from samoyed.path_engine.search import find_attack_paths
from samoyed.scenarios.k8s import CompromisedSaScenario, PodEscapeScenario
from samoyed.sessions import SESSION_STORE


def _k8s_snapshot(tmp_path, monkeypatch, session_id: str):
    monkeypatch.chdir(tmp_path)
    return SESSION_STORE.load_fixture("k8s-lab", session_id=session_id).snapshot


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
    assert ("READS", "SecretStore", None) in grants


def test_rule_grants_cluster_admin():
    rules = [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]
    grants = rule_grants(rules)
    assert ("CAN_ACCESS", "ManagementEndpoint", None) in grants
    assert ("CONTROLS", "Workload", "rbac:pods:create") in grants
    assert ("CONTROLS", "Workload", "rbac:pods:exec") in grants


def test_rule_grants_pods_exec_only():
    rules = [{"verbs": ["create"], "resources": ["pods/exec"], "apiGroups": [""]}]
    grants = rule_grants(rules)
    assert ("CONTROLS", "Workload", "rbac:pods:exec") in grants
    assert not any(g[2] == "rbac:pods:create" for g in grants)


def test_rule_grants_pods_create_only():
    rules = [{"verbs": ["create"], "resources": ["pods"], "apiGroups": [""]}]
    grants = rule_grants(rules)
    assert ("CONTROLS", "Workload", "rbac:pods:create") in grants
    assert not any(g[2] == "rbac:pods:exec" for g in grants)


def test_k8s_fixture_deployer_reaches_irsa_via_pod_create(tmp_path, monkeypatch):
    snapshot = _k8s_snapshot(tmp_path, monkeypatch, "k8s-deploy-pivot")
    deployer = next(
        nid
        for nid, n in snapshot.nodes.items()
        if n.props.get("name") == "deployer-sa"
    )
    cloud_role = next(
        nid
        for nid, n in snapshot.nodes.items()
        if "eks-workload-admin" in str(n.props.get("native_id", ""))
    )
    paths = find_attack_paths(
        snapshot,
        start_node_id=deployer,
        end_node_id=cloud_role,
        max_depth=8,
    )
    assert paths
    rels = [s.rel_type for s in paths[0].steps]
    assert "EXECUTES_AS" in rels
    assert "PROJECTS_TO" in rels


def test_k8s_fixture_compromised_sa_scenario(tmp_path, monkeypatch):
    snapshot = _k8s_snapshot(tmp_path, monkeypatch, "k8s-test")
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


def test_k8s_fixture_pod_escape_scenario(tmp_path, monkeypatch):
    snapshot = _k8s_snapshot(tmp_path, monkeypatch, "k8s-escape-test")
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


def test_k8s_fixture_pod_escape_reaches_node_role(tmp_path, monkeypatch):
    snapshot = _k8s_snapshot(tmp_path, monkeypatch, "k8s-escape-cloud")
    pod = next(n for n in snapshot.nodes.values() if n.props.get("name") == "evil-pod")
    node_role = next(
        nid
        for nid, n in snapshot.nodes.items()
        if "eks-node-role" in str(n.props.get("native_id") or n.props.get("arn") or "")
    )
    paths = find_attack_paths(
        snapshot,
        start_node_id=pod.node_id,
        end_node_id=node_role,
        max_depth=8,
    )
    assert paths
    rels = [s.rel_type for s in paths[0].steps]
    assert "HAS_ESCAPE_SURFACE" in rels
    assert "CAN_ESCAPE_TO" in rels
    assert "EXECUTES_AS" in rels
