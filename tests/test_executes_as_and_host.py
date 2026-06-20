from __future__ import annotations

from samoyed.attack.analyzer import execution_role_nodes
from samoyed.attack.host_pivot import HostPivotSpec, apply_host_pivot
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.scenarios.host_compromise import HostCompromiseScenario


def test_lambda_executes_as_role():
    builder = GraphBuilder("exec-test")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:role/lambda-admin",
        props={"native_kind": "Role"},
    )
    fn = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:123:function:tool",
        props={"resource_type": "LambdaFunction"},
    )
    builder.add_edge(src_id=fn, rel_type="EXECUTES_AS", dst_id=role)
    roles = execution_role_nodes(builder.snapshot)
    assert role in roles


def test_lambda_update_code_targets_execution_role():
    from samoyed.attack.analyzer import apply_attack_analysis

    builder = GraphBuilder("exec-test")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/dev",
        props={"is_caller": True, "native_kind": "User"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:role/lambda-admin",
        props={"native_kind": "Role"},
    )
    fn = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:123:function:tool",
        props={"resource_type": "LambdaFunction"},
    )
    builder.add_edge(src_id=fn, rel_type="EXECUTES_AS", dst_id=role)
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=fn,
        props={"action": "lambda:UpdateFunctionCode"},
    )
    edges = apply_attack_analysis(builder, provider=CloudProvider.AWS)
    privesc = [e for e in builder.snapshot.edges if e.rel_type == "CAN_PRIVESC_TO"]
    assert any(e.dst_id == role for e in privesc)
    assert any(e.pattern.id == "aws-lambda-update-code" for e in edges)


def test_host_pivot_logged_in_session():
    builder = GraphBuilder("host-test")
    apply_host_pivot(
        builder,
        HostPivotSpec(
            host_native_id="host:laptop:1",
            interactive_sessions=[],
            credential_stores=[],
        ),
    )
    host = next(n for n in builder.snapshot.nodes.values() if n.props.get("native_kind") == "CompromisedHost")
    assert host.props.get("is_scenario_start")


def test_host_compromise_scenario_reaches_cloud_identity():
    from samoyed.graph.sample_host import build_sample_host_graph

    snapshot = build_sample_host_graph("host-scenario-test")
    host = next(n for n in snapshot.nodes.values() if n.props.get("native_kind") == "CompromisedHost")
    paths = HostCompromiseScenario().run(snapshot, host.node_id)
    assert len(paths) >= 1
    node_ids = {nid for p in paths for nid in p.node_ids}
    assert any("dev-bob" in str(nid) or "bob@corp" in str(nid) for nid in node_ids)
