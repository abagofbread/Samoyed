from __future__ import annotations

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.attack.mitre import (
    enrich_graph_edges,
    export_mitre_catalog,
    mitre_props_for_edge,
    techniques_for_action,
    techniques_for_pattern,
)
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.cloud.ontology import export_ontology
from samoyed.graph.builder import GraphBuilder


def test_lambda_update_code_maps_to_mitre():
    techs = techniques_for_action("lambda:UpdateFunctionCode")
    ids = {t.id for t in techs}
    assert "T1578.005" in ids
    assert "T1059.009" in ids


def test_pattern_mitre_mapping():
    techs = techniques_for_pattern("aws-ssm-send-command")
    assert any(t.id == "T1021.008" for t in techs)


def test_mitre_enrich_controles_edge():
    props = mitre_props_for_edge("CONTROLS", {"action": "ssm:SendCommand"})
    assert "T1021.008" in props["mitre_technique_ids"]


def test_mitre_enrich_executes_as_imds():
    props = mitre_props_for_edge("EXECUTES_AS", {"source": "instance-profile"})
    assert "T1552.005" in props["mitre_technique_ids"]


def test_apply_attack_analysis_annotates_privesc_edges():
    builder = GraphBuilder("mitre-test")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/leaked",
        props={"is_caller": True, "native_kind": "User"},
    )
    ec2 = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:arn:aws:ec2:us-east-1:123:instance/i-1",
        props={"resource_type": "EC2Instance"},
    )
    builder.add_edge(
        src_id=user,
        rel_type="CONTROLS",
        dst_id=ec2,
        props={"action": "ssm:SendCommand"},
    )

    apply_attack_analysis(builder, provider=CloudProvider.AWS)

    privesc = [e for e in builder.snapshot.edges if e.rel_type == "CAN_PRIVESC_TO"]
    assert privesc
    assert "T1021.008" in privesc[0].props.get("mitre_technique_ids", [])

    reads_edges = [e for e in builder.snapshot.edges if e.rel_type == "CONTROLS"]
    assert reads_edges[0].props.get("mitre_technique_ids")


def test_enrich_graph_edges_annotates_assume_role():
    builder = GraphBuilder("mitre-assume")
    user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:user/a",
        props={"is_caller": True},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::123:role/b",
        props={"native_kind": "Role"},
    )
    builder.add_edge(src_id=user, rel_type="CAN_ASSUME_ROLE", dst_id=role)

    count = enrich_graph_edges(builder.snapshot)
    assert count > 0
    edge = builder.snapshot.edges[0]
    assert "T1078.004" in edge.props.get("mitre_technique_ids", [])


def test_ontology_exports_mitre_reference():
    data = export_ontology()
    assert data["mitre_framework"] == "ATT&CK Enterprise"
    assert "cloud" in data["mitre_matrix_url"]


def test_mitre_catalog_export():
    catalog = export_mitre_catalog()
    assert catalog["technique_count"] >= 20
    assert "aws-ssm-send-command" in catalog["pattern_mappings"]
