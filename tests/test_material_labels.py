"""Human labels for pivot materials."""

from __future__ import annotations

from samoyed.collectors.assess import assess_text
from samoyed.enrichment.apply import apply_enrichment_report
from samoyed.enrichment.labels import (
    classify_finding,
    is_weak_label,
    material_summary,
    relabel_material_node,
)
from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder


def test_classify_password_and_private_key():
    assert classify_finding("generic_credential_file", 'password = "hunter2"') == "Hardcoded password"
    assert (
        classify_finding("generic_credential_file", "-----BEGIN RSA PRIVATE KEY-----")
        == "Private key"
    )
    assert "Secrets Manager" in classify_finding(
        "generic_credential_file", 'resource "aws_secretsmanager_secret"'
    )


def test_never_emits_credential_file_or_kind_slug():
    assert classify_finding("generic_credential_file", "something opaque") == "Hardcoded credential"
    summary = material_summary(
        kind="generic_credential_file",
        locator="main.tf:138:generic_credential_file",
        evidence={"file": "main.tf", "line": 138, "match": 'password = "***"'},
        name_hints=["RDS_CREDS", "aws-goat-db", "ecs-task-role", "bucket_tf_files"],
    )
    assert "Hardcoded password" in summary
    assert "main.tf:138" in summary
    assert "aws-goat-db" in summary
    assert "Credential file" not in summary
    assert "generic_credential_file" not in summary
    assert "ecs-task-role" not in summary
    assert "RDS_CREDS" not in summary


def test_weak_label_detection():
    assert is_weak_label("Credential file: main.tf:138:generic_credential_file")
    assert is_weak_label("AWS access key (environment): .env:AKIA****")
    assert is_weak_label("generic_credential_file")
    assert is_weak_label("material:generic_credential_file:fixturehash01")
    assert not is_weak_label("Hardcoded password in main.tf:138 → aws-goat-db")


def test_assess_stamps_summary():
    text = 'password = "fixture-goat-db-password-not-real"\n'
    mats = assess_text(text, path="modules/module-2/main.tf")
    assert mats
    generic = next(m for m in mats if m["kind"] == "generic_credential_file")
    assert generic["finding"] == "Hardcoded password"
    assert "Hardcoded password" in generic["summary"]
    assert "main.tf" in generic["summary"]
    assert "generic_credential_file" not in generic["summary"]
    assert "Credential file" not in generic["summary"]


def test_imported_material_node_has_human_label():
    builder = GraphBuilder("mat-label")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:lab",
        props={"resource_type": "EC2Instance", "name": "lab"},
    )
    report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "bindings": [
            {
                "target_ref": "lab",
                "materials": [
                    {
                        "kind": "generic_credential_file",
                        "locator": "modules/module-2/main.tf:476",
                        "name_hints": ["RDS_CREDS", "aws-goat-db", "ecs-task-role"],
                        "confidence": "explicit",
                        "evidence": {
                            "file": "modules/module-2/main.tf",
                            "line": 476,
                            "match": 'password = "***"',
                        },
                    }
                ],
            }
        ],
    }
    apply_enrichment_report(builder, report, default_target_node_id=host)
    mat = next(
        n for n in builder.snapshot.nodes.values() if n.props.get("material_kind") == "generic_credential_file"
    )
    assert mat.props["display_name"].startswith("Hardcoded password")
    assert "main.tf" in mat.props["display_name"]
    assert "aws-goat-db" in mat.props["display_name"]
    assert "RDS_CREDS" not in mat.props["display_name"]
    assert mat.props.get("finding") == "Hardcoded password"
    assert "generic_credential_file" not in mat.props["display_name"]
    assert "Credential file" not in mat.props["display_name"]


def test_relabel_repairs_legacy_catalog_title():
    props = {
        "native_kind": "PivotMaterial",
        "material_kind": "aws_access_key_env",
        "locator": ".env:AKIA****************MPLE",
        "display_name": "AWS access key (environment): .env:AKIA****************MPLE",
        "summary": "AWS access key (environment): .env:AKIA****************MPLE",
        "evidence": {"file": ".env", "line": 1, "match": "AKIA****************MPLE"},
    }
    relabel_material_node(props)
    assert props["display_name"].startswith("AWS access key")
    assert "(environment):" not in props["display_name"]
    assert "in .env" in props["display_name"]


def test_old_report_without_summary_gets_human_label_on_import():
    builder = GraphBuilder("old-report")
    host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="EC2Instance:lab",
        props={"name": "lab"},
    )
    report = {
        "enrichment_version": 1,
        "collector": "static-repo",
        "collector_mode": "static",
        "bindings": [
            {
                "target_ref": "lab",
                "materials": [
                    {
                        "kind": "generic_credential_file",
                        "locator": "main.tf:138:generic_credential_file",
                        "name_hints": ["RDS_CREDS", "aws-goat-db", "ecs-instance-role", "bucket_tf_files"],
                        "confidence": "explicit",
                        "evidence": {
                            "file": "main.tf",
                            "line": 138,
                            "match": 'password               = "T2kV********brKS"',
                        },
                    }
                ],
            }
        ],
    }
    apply_enrichment_report(builder, report, default_target_node_id=host)
    mat = next(n for n in builder.snapshot.nodes.values() if n.props.get("material_kind"))
    assert mat.props["display_name"] == "Hardcoded password in main.tf:138 → aws-goat-db"


def test_material_summary_fallback():
    s = material_summary(
        kind="aws_access_key_env",
        locator=".env:AKIA****************",
        evidence={"file": ".env", "line": 1, "match": "AKIA****************"},
    )
    assert s.startswith("AWS access key")
    assert ".env" in s
    assert "(environment)" not in s
