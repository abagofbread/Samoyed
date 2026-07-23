from __future__ import annotations

from pathlib import Path

from samoyed.cloud.concepts import ConceptType
from samoyed.collectors.assess import assess_tree
from samoyed.collectors.correlate import extract_terraform_names, secret_fingerprint
from samoyed.collectors.static import collect_static_source
from samoyed.enrichment.apply import apply_enrichment_report
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.refs import resolve_node_ref


GOAT_SNIPPET = '''
resource "aws_db_instance" "database-instance" {
  identifier = "aws-goat-db"
  username   = "root"
  password   = "fixture-goat-db-password-not-real"
}

resource "aws_iam_role" "ecs-instance-role" {
  name = "ecs-instance-role"
  assume_role_policy = jsonencode({ "Version" = "2012-10-17" })
}

resource "aws_secretsmanager_secret" "rds_creds" {
  name = "RDS_CREDS"
}

resource "aws_secretsmanager_secret_version" "secret_version" {
  secret_string = <<EOF
   { "username": "root", "password": "fixture-goat-db-password-not-real" }
EOF
}
'''


def test_extract_terraform_names():
    names = extract_terraform_names(GOAT_SNIPPET, source_path="main.tf")
    by_kind = {n["kind"]: n["name"] for n in names}
    assert by_kind["db_instance"] == "aws-goat-db"
    assert by_kind["iam_role"] == "ecs-instance-role"
    assert by_kind["secretsmanager_secret"] == "RDS_CREDS"


def test_credential_reuse_across_files(tmp_path: Path):
    root = tmp_path / "mod"
    root.mkdir()
    (root / "main.tf").write_text(GOAT_SNIPPET, encoding="utf-8")
    (root / "startup.sh").write_text(
        "mysql -h $RDS_ENDPOINT -P 3306 -u root -pfixture-goat-db-password-not-real\n",
        encoding="utf-8",
    )
    materials, declared, scanned = assess_tree(root)
    assert scanned >= 2
    assert any(r["name"] == "RDS_CREDS" for r in declared)
    reused = [m for m in materials if int(m.get("reuse_count") or 0) >= 2]
    assert reused, materials
    fps = {m["secret_fingerprint"] for m in reused}
    assert len(fps) == 1
    assert fps.pop().startswith("sha256:")
    # Same value collapses to one material; sites live on seen_at.
    assert len(reused) == 1
    assert len(reused[0].get("seen_at") or []) >= 2
    # raw secret never retained
    assert all("_secret_value" not in m for m in materials)
    assert "fixture-goat-db-password-not-real" not in str(materials)
    # Impact hint is the DB instance, not the Secrets Manager wrapper name.
    assert any("aws-goat-db" in (m.get("name_hints") or []) for m in reused)


def test_db_impact_collapses_password_endpoint_and_sm_refs(tmp_path: Path):
    """Password + RDS_ENDPOINT + SM resource refs → one material (locations on seen_at)."""
    root = tmp_path / "goat"
    root.mkdir()
    (root / "main.tf").write_text(
        '''
resource "aws_db_instance" "database-instance" {
  identifier = "aws-goat-db"
  username   = "root"
  password   = "fixture-goat-db-password-not-real"
}
resource "aws_secretsmanager_secret" "rds_creds" {
  name = "RDS_CREDS"
}
resource "aws_secretsmanager_secret" "rds_creds_dup" {
  name = "RDS_CREDS_COPY"
}
''',
        encoding="utf-8",
    )
    (root / "startup.sh").write_text(
        "mysql -h $RDS_ENDPOINT -P 3306 -u root -pfixture-goat-db-password-not-real\n",
        encoding="utf-8",
    )
    (root / "task_definition.json").write_text(
        '[{"name": "RDS_ENDPOINT", "value": "aws-goat-db.xxxx.us-east-1.rds.amazonaws.com"}]\n',
        encoding="utf-8",
    )
    materials, _declared, _scanned = assess_tree(root)
    db_mats = [
        m
        for m in materials
        if m.get("impact_key") == "db_instance:aws-goat-db"
        or any(
            isinstance(t, dict) and t.get("name") == "aws-goat-db"
            for t in (m.get("impact_targets") or [])
        )
    ]
    assert len(db_mats) == 1, [m.get("locator") for m in materials]
    mat = db_mats[0]
    seen = mat.get("seen_at") or []
    assert len(seen) >= 3, seen
    assert any("startup" in s for s in seen)
    assert any("main.tf" in s for s in seen)
    assert any("task_definition" in s or "RDS_ENDPOINT" in s for s in seen)
    # Prefer concrete password finding over SM/endpoint noise.
    assert "password" in str(mat.get("finding") or "").lower() or mat.get("secret_fingerprint")

    builder = GraphBuilder("impact-collapse-graph")
    host = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={"native_kind": "Role", "name": "ecs-instance-role"},
    )
    rds = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="RDSInstance:aws-goat-db",
        props={"resource_type": "RDSInstance", "name": "aws-goat-db"},
    )
    report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "source_root": str(root),
        "bindings": [{"target_ref": "ecs-instance-role", "materials": materials}],
    }
    apply_enrichment_report(builder, report, default_target_node_id=host)
    mats = [
        n
        for n in builder.snapshot.nodes.values()
        if n.props.get("native_kind") == "PivotMaterial"
        or str(n.props.get("native_id") or "").startswith("material:")
    ]
    # One collapsed DB credential node — not one per file/line.
    db_nodes = [
        n
        for n in mats
        if "goat-db" in str(n.props.get("display_name") or n.props.get("summary") or "").lower()
        or n.props.get("impact_key") == "db_instance:aws-goat-db"
        or n.props.get("secret_fingerprint")
    ]
    assert len(db_nodes) == 1, [(n.props.get("display_name"), n.props.get("native_id")) for n in mats]
    node = db_nodes[0]
    # Location is not the node title; sites are on the edge / seen_at.
    assert "in main.tf" not in str(node.props.get("display_name") or "")
    assert "in startup" not in str(node.props.get("display_name") or "")
    edges = [
        e
        for e in builder.snapshot.edges
        if e.src_id == host and e.rel_type == "HAS_MATERIAL" and e.dst_id == node.node_id
    ]
    assert len(edges) == 1
    assert len(edges[0].props.get("seen_at") or []) >= 3
    assert any(e.dst_id == rds for e in builder.snapshot.edges if e.rel_type == "UNLOCKS")


def test_fingerprint_collapse_single_graph_node():
    """Same secret at two locators → one PivotMaterial; locations on HAS_MATERIAL."""
    from samoyed.enrichment.report import material_native_id

    fp = secret_fingerprint("fixture-goat-db-password-not-real")
    id_a = material_native_id(
        "generic_credential_file",
        "main.tf:3:generic_credential_file",
        fingerprint=fp,
    )
    id_b = material_native_id(
        "database_connection_string",
        "startup.sh:1:database_connection_string",
        fingerprint=fp,
    )
    assert id_a == id_b
    assert id_a.startswith("material:fp:")

    builder = GraphBuilder("fp-collapse")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:lab",
        props={"native_kind": "EC2Instance", "name": "lab"},
    )
    rds = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="RDSInstance:aws-goat-db",
        props={"resource_type": "RDSInstance", "name": "aws-goat-db"},
    )
    report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "source_root": "/tmp/fp-collapse",
        "bindings": [
            {
                "target_ref": "lab",
                "materials": [
                    {
                        "kind": "generic_credential_file",
                        "locator": "main.tf:3:generic_credential_file",
                        "confidence": "explicit",
                        "secret_fingerprint": fp,
                        "name_hints": ["aws-goat-db"],
                        "impact_targets": [{"name": "aws-goat-db", "kind": "db_instance"}],
                        "evidence": {"file": "main.tf"},
                    },
                    {
                        "kind": "database_connection_string",
                        "locator": "startup.sh:1:database_connection_string",
                        "confidence": "explicit",
                        "secret_fingerprint": fp,
                        "name_hints": ["aws-goat-db"],
                        "impact_targets": [{"name": "aws-goat-db", "kind": "db_instance"}],
                        "evidence": {"file": "startup.sh"},
                    },
                ],
            }
        ],
    }
    stats = apply_enrichment_report(builder, report, default_target_node_id=host)
    assert stats["materials_applied"] == 2
    mats = [
        n
        for n in builder.snapshot.nodes.values()
        if n.props.get("native_kind") == "PivotMaterial"
        or str(n.props.get("native_id") or "").startswith("material:")
    ]
    assert len(mats) == 1
    mat = mats[0]
    assert mat.props.get("secret_fingerprint") == fp
    seen = mat.props.get("seen_at") or []
    assert "main.tf:3:generic_credential_file" in seen
    assert "startup.sh:1:database_connection_string" in seen
    edges = [
        e
        for e in builder.snapshot.edges
        if e.src_id == host and e.rel_type == "HAS_MATERIAL" and e.dst_id == mat.node_id
    ]
    assert len(edges) == 1
    edge_seen = edges[0].props.get("seen_at") or []
    assert "main.tf:3:generic_credential_file" in edge_seen
    assert "startup.sh:1:database_connection_string" in edge_seen
    unlocks = [e for e in builder.snapshot.edges if e.rel_type == "UNLOCKS" and e.src_id == mat.node_id]
    assert any(e.dst_id == rds for e in unlocks)


def test_name_hints_reference_graph_nodes():
    builder = GraphBuilder("name-hints")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:lab",
        props={"native_kind": "EC2Instance"},
    )
    rds = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="RDSInstance:aws-goat-db",
        props={"native_kind": "RDSInstance", "name": "aws-goat-db", "resource_type": "RDSInstance"},
    )
    assert resolve_node_ref(builder.snapshot, "aws-goat-db") == rds

    report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "bindings": [
            {
                "target_ref": "unbound",
                "materials": [
                    {
                        "kind": "generic_credential_file",
                        "locator": "main.tf:3:generic_credential_file",
                        "confidence": "explicit",
                        "secret_fingerprint": secret_fingerprint("fixture-goat-db-password-not-real"),
                        "reuse_count": 2,
                        "also_seen_in": ["startup.sh:1:database_connection_string"],
                        "name_hints": ["aws-goat-db"],
                        "impact_targets": [{"name": "aws-goat-db", "kind": "db_instance"}],
                        "evidence": {"file": "main.tf"},
                    }
                ],
            }
        ],
    }
    stats = apply_enrichment_report(builder, report, default_target_node_id=host)
    assert stats["materials_applied"] == 1
    assert stats["name_matches"]
    unlocks = [e for e in builder.snapshot.edges if e.rel_type == "UNLOCKS"]
    unlocked = {e.dst_id for e in unlocks}
    # DB password material unlocks the inventored RDS instance only.
    assert rds in unlocked


def test_collect_module_like_tree(tmp_path: Path):
    root = tmp_path / "module-2"
    root.mkdir()
    (root / "main.tf").write_text(GOAT_SNIPPET, encoding="utf-8")
    report = collect_static_source(root)
    assert report["material_count"] >= 1
    assert report.get("declared_resources")
    assert report.get("credential_reuse_findings", 0) >= 1 or any(
        int(m.get("reuse_count") or 0) > 1
        for b in report.get("bindings") or []
        for m in b.get("materials") or []
    )
