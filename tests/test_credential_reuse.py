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
    # raw secret never retained
    assert all("_secret_value" not in m for m in materials)
    assert "fixture-goat-db-password-not-real" not in str(materials)
    # TF name hints attached
    assert any("RDS_CREDS" in (m.get("name_hints") or []) for m in reused)


def test_name_hints_reference_graph_nodes():
    builder = GraphBuilder("name-hints")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:lab",
        props={"native_kind": "EC2Instance"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:1:secret:RDS_CREDS",
        props={"native_kind": "Secret", "name": "RDS_CREDS", "resource_type": "Secret"},
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ecs-instance-role",
        props={"native_kind": "Role", "name": "ecs-instance-role"},
    )
    assert resolve_node_ref(builder.snapshot, "RDS_CREDS") == secret
    assert resolve_node_ref(builder.snapshot, "ecs-instance-role") == role

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
                        "name_hints": ["RDS_CREDS", "aws-goat-db", "ecs-instance-role"],
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
    # Cred material maps outward to the secret + identity it correlates with.
    assert secret in unlocked
    assert role in unlocked


def test_collect_module_like_tree(tmp_path: Path):
    root = tmp_path / "module-2"
    root.mkdir()
    (root / "main.tf").write_text(GOAT_SNIPPET, encoding="utf-8")
    report = collect_static_source(root)
    assert report["material_count"] >= 2
    assert report.get("declared_resources")
    assert report.get("credential_reuse_findings", 0) >= 1
