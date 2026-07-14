from __future__ import annotations

from samoyed.attack.k8s_pivot import enrich_k8s_deploy_pivot
from samoyed.attack.surface import enrich_attack_surface
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.path_engine.search import find_attack_paths


def _build_k8s_lab_graph() -> GraphBuilder:
    builder = GraphBuilder("k8s-pivot-test")
    deployer = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="kubernetes:serviceaccount:platform:deployer",
        props={"native_kind": "ServiceAccount", "namespace": "platform", "name": "deployer"},
    )
    victim_sa = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="kubernetes:serviceaccount:platform:secrets-writer",
        props={"native_kind": "ServiceAccount", "namespace": "platform", "name": "secrets-writer"},
    )
    irsa_sa = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="kubernetes:serviceaccount:platform:irsa-sa",
        props={"native_kind": "ServiceAccount", "namespace": "platform", "name": "irsa-sa"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="kubernetes:secret:platform:vault-bootstrap-token",
        props={"namespace": "platform", "name": "vault-bootstrap-token"},
    )
    cloud_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/eks-irsa-vault-reader",
        props={"native_kind": "Role", "provider": "aws"},
    )
    workload = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="kubernetes:workload:*",
        props={"display_name": "Any pod (wildcard)"},
    )
    pod = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="kubernetes:pod:platform:harvest-pod",
        props={"native_kind": "Pod", "namespace": "platform", "name": "harvest-pod", "service_account": "irsa-sa"},
    )

    builder.add_edge(
        src_id=deployer,
        rel_type="CONTROLS",
        dst_id=workload,
        props={
            "action": "rbac:pods:create",
            "namespace": "platform",
            "source": "k8s-rbac-enum",
        },
    )
    builder.add_edge(
        src_id=victim_sa,
        rel_type="READS",
        dst_id=secret,
        props={"role": "secret-reader"},
    )
    builder.add_edge(
        src_id=irsa_sa,
        rel_type="PROJECTS_TO",
        dst_id=cloud_role,
        props={"binding_type": "IRSA"},
    )
    builder.add_edge(
        src_id=pod,
        rel_type="EXECUTES_AS",
        dst_id=irsa_sa,
        props={"service_account": "irsa-sa"},
    )
    return builder


def test_deploy_pivot_reaches_other_service_account():
    builder = _build_k8s_lab_graph()
    deployer = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if n.props.get("name") == "deployer"
    )
    irsa_sa = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if n.props.get("name") == "irsa-sa"
    )
    cloud_role = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if "eks-irsa-vault-reader" in str(n.props.get("native_id", ""))
    )

    stats = enrich_k8s_deploy_pivot(builder)
    assert stats["deploy_exec_as"] >= 2

    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=deployer,
        end_node_id=cloud_role,
        max_depth=8,
    )
    assert paths
    rels = [s.rel_type for s in paths[0].steps]
    assert "EXECUTES_AS" in rels
    assert "PROJECTS_TO" in rels


def test_exec_pivot_inherits_pod_service_account():
    builder = _build_k8s_lab_graph()
    exec_user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="kubernetes:serviceaccount:platform:exec-user",
        props={"native_kind": "ServiceAccount", "namespace": "platform", "name": "exec-user"},
    )
    workload = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if n.props.get("native_id") == "kubernetes:workload:*"
    )
    builder.add_edge(
        src_id=exec_user,
        rel_type="CONTROLS",
        dst_id=workload,
        props={"action": "rbac:pods:exec", "namespace": "platform"},
    )

    stats = enrich_k8s_deploy_pivot(builder)
    assert stats["exec_into_pods"] >= 1
    assert stats["exec_exec_as"] >= 1

    irsa_sa = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if n.props.get("name") == "irsa-sa"
    )
    paths = find_attack_paths(
        builder.snapshot,
        start_node_id=exec_user,
        end_node_id=irsa_sa,
        max_depth=4,
    )
    assert paths
    assert paths[0].steps[-1].rel_type == "EXECUTES_AS"


def test_enrich_attack_surface_includes_k8s_deploy_pivot():
    builder = _build_k8s_lab_graph()
    stats = enrich_attack_surface(builder)
    assert stats.get("deploy_exec_as", 0) >= 1
