from __future__ import annotations

import json

from samoyed.collectors.assess import assess_text
from samoyed.enrichment.redact import redact_evidence, redact_secret_text


def test_redact_aws_access_key():
    raw = "AKIAIOSFODNN7EXAMPLE"
    out = redact_secret_text(raw)
    assert out.startswith("AKIA")
    assert "IOSFODNN7E" not in out or "*" in out
    assert out.endswith("MPLE")
    assert "*" in out


def test_redact_secret_assignment():
    raw = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    out = redact_secret_text(raw)
    assert "wJalrXUtnFEMI" not in out
    assert out.lower().startswith("aws_secret_access_key=")
    assert "*" in out


def test_assess_finds_terraform_password():
    text = 'password               = "fixture-goat-db-password-not-real"\n"password": "fixture-other-secret-not-real"\n'
    from samoyed.collectors.correlate import correlate_materials

    materials = correlate_materials(assess_text(text, path="main.tf"))
    assert any(m["kind"] == "generic_credential_file" for m in materials)
    for m in materials:
        assert "fixture-goat-db-password-not-real" not in json.dumps(m)
        assert "fixture-other-secret-not-real" not in json.dumps(m)
        assert "_secret_value" not in m


def test_assess_finds_mysql_and_rds_endpoint():
    text = 'mysql -h $RDS_ENDPOINT -P 3306 -u root -pfixture-goat-db-password-not-real\n"name": "RDS_ENDPOINT"\n'
    from samoyed.collectors.correlate import correlate_materials

    materials = correlate_materials(assess_text(text, path="startup.sh"))
    kinds = {m["kind"] for m in materials}
    assert "database_connection_string" in kinds
    blob = json.dumps(materials)
    assert "fixture-goat-db-password-not-real" not in blob


def test_redact_evidence_nested():
    evidence = redact_evidence({"file": ".env", "match": "AKIAIOSFODNN7EXAMPLE"})
    assert "AKIA" in evidence["match"]
    assert "*" in evidence["match"]
