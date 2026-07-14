from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from samoyed.api.main import app
from samoyed.client.azure_report import collect_azure_iam_report
from samoyed.credentials.azure import AzureCredential
from samoyed.fixtures.registry import read_fixture_bytes
from samoyed.path_engine.search import find_attack_paths
from samoyed.sessions import SESSION_STORE

client = TestClient(app)


def _load_azure_lab(tmp_path, monkeypatch, session_id: str = "lab-azure-fixture"):
    monkeypatch.chdir(tmp_path)
    record = SESSION_STORE.load_fixture("lab-azure", session_id=session_id)
    snapshot = record.snapshot
    start = SESSION_STORE.find_caller_node(record)
    return record, snapshot, start


def test_azure_collected_sample_imports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = read_fixture_bytes("azure-collected-sample")
    record = SESSION_STORE.create_import_session(
        "iam-report",
        payload,
        session_id="azure-sample-import",
    )
    assert record.metadata.get("provider") == "azure"
    names = {n.props.get("name") for n in record.snapshot.nodes.values()}
    assert "corpartifactsdev" in names or any("corpartifactsdev" in str(v) for v in names)
    assert any("KeyVault" in str(n.props.get("resource_type", n.props.get("type", ""))) for n in record.snapshot.nodes.values())


def test_lab_azure_fixture_structure(tmp_path, monkeypatch):
    _, snapshot, _ = _load_azure_lab(tmp_path, monkeypatch, "azure-structure")
    native_ids = {n.props.get("native_id") for n in snapshot.nodes.values()}
    assert "StorageAccount:corpartifactsdev" in native_ids
    assert "KeyVaultSecret:corp-kv-prod/customer-pii-export" in native_ids
    assert "WebApp:marketing-api" in native_ids


def test_lab_azure_sp_reaches_dev_sandbox_secret(tmp_path, monkeypatch):
    _, snapshot, start = _load_azure_lab(tmp_path, monkeypatch, "azure-dev-secret")
    target = next(
        nid
        for nid, n in snapshot.nodes.items()
        if n.props.get("name") == "api-hubspot-sandbox"
        or n.props.get("native_id") == "KeyVaultSecret:corp-kv-dev/api-hubspot-sandbox"
    )
    paths = find_attack_paths(snapshot, start_node_id=start, end_node_id=target, max_depth=8)
    assert paths, "leaked CI SP should READ dev sandbox secret directly"


def test_lab_azure_sp_reaches_prod_pii_via_webapp_mi(tmp_path, monkeypatch):
    _, snapshot, start = _load_azure_lab(tmp_path, monkeypatch, "azure-prod-pii")
    target = next(
        nid
        for nid, n in snapshot.nodes.items()
        if n.props.get("name") == "customer-pii-export"
        or n.props.get("native_id") == "KeyVaultSecret:corp-kv-prod/customer-pii-export"
    )
    paths = find_attack_paths(snapshot, start_node_id=start, end_node_id=target, max_depth=10)
    assert paths, "SP should reach prod PII via web app control → MI → KV read"
    rels = [s.rel_type for s in paths[0].steps]
    assert "CONTROLS" in rels or "EXECUTES_AS" in rels


def test_import_azure_sample_via_api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = read_fixture_bytes("azure-collected-sample")
    res = client.post(
        "/api/sessions/import",
        data={"connector": "iam-report", "caller_arn": "azure:serviceprincipal:3f3f3f3f-aaaa-bbbb-cccc-dddddddddddd"},
        files={"file": ("azure.json", payload, "application/json")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["metadata"]["provider"] == "azure"


@patch("samoyed.client.azure_report.AzureCredential.client")
@patch("samoyed.credentials.azure._require_azure")
def test_collect_azure_iam_report_maps_rbac_to_grants(mock_require, mock_client):
    mock_require.return_value = (MagicMock(), MagicMock())
    cred = AzureCredential(
        tenant_id="tenant",
        client_id="3f3f3f3f-aaaa-bbbb-cccc-dddddddddddd",
        client_secret="secret",
        subscription_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    )

    storage = MagicMock()
    kv = MagicMock()
    auth = MagicMock()

    def factory(service: str, region=None):
        return {"storage": storage, "keyvault": kv, "authorization": auth}[service]

    mock_client.side_effect = factory

    account = MagicMock()
    account.name = "corpartifactsdev"
    account.id = "/subscriptions/a1b2c3d4/resourceGroups/rg-dev/providers/Microsoft.Storage/storageAccounts/corpartifactsdev"
    storage.storage_accounts.list.return_value = [account]

    vault = MagicMock()
    vault.name = "corp-kv-dev"
    vault.id = "/subscriptions/a1b2c3d4/resourceGroups/rg-dev/providers/Microsoft.KeyVault/vaults/corp-kv-dev"
    vault.properties.vault_uri = None
    kv.vaults.list.return_value = [vault]

    role_def = MagicMock()
    role_def.role_name = "Storage Blob Data Reader"
    auth.role_definitions.get_by_id.return_value = role_def

    assignment = MagicMock()
    assignment.name = "ra-1"
    assignment.role_definition_id = "/subscriptions/a1b2c3d4/providers/Microsoft.Authorization/roleDefinitions/reader"
    assignment.principal_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assignment.principal_type = "ServicePrincipal"
    assignment.scope = account.id
    auth.role_assignments.list_for_subscription.return_value = [assignment]

    report = collect_azure_iam_report(cred)
    assert report["provider"] == "azure"
    assert report["collected_via"] == "live-azure-api"
    assert any(r["type"] == "StorageAccount" for r in report["resources"])
    assert any(g["rel"] == "READS" and g["to"] == "StorageAccount:corpartifactsdev" for g in report["grants"])
