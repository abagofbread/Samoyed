"""Azure enumerator edge concreteness + multi-hop path coverage."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.capabilities import map_azure_role
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.cloud.providers import normalize_scope_id
from samoyed.credentials.protocol import EnumContext, ScopeBoundary
from samoyed.enumerators.azure.entitlement import AzureEntitlementEnumerator
from samoyed.enumerators.azure.targets import targets_for_assignment
from samoyed.graph.builder import GraphBuilder
from samoyed.ingest.concept_normalizer import ConceptNormalizer
from samoyed.path_engine.search import find_attack_paths


SUB = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
SCOPE = f"azure:subscription:{SUB}"


def test_normalize_legacy_azure_scope_id():
    legacy = f"azure:scope:subscription:{SUB}"
    assert normalize_scope_id(legacy) == SCOPE


def test_targets_prefer_inventored_webapp_not_wildcard():
    mapping = map_azure_role("Website Contributor")
    assert mapping is not None
    scope = (
        f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/marketing-api"
    )
    targets = targets_for_assignment(scope, mapping, {"WebApp:marketing-api"})
    assert targets == [("WebApp:marketing-api", "CONTROLS")]
    assert not any("*" in t for t, _ in targets)


def test_entitlement_emits_concrete_kv_and_webapp_targets():
    sp_oid = "3f3f3f3f-aaaa-bbbb-cccc-dddddddddddd"
    assignment = SimpleNamespace(
        name="ra-1",
        role_definition_id=(
            f"/subscriptions/{SUB}/providers/Microsoft.Authorization/"
            "roleDefinitions/website-contributor"
        ),
        principal_type="ServicePrincipal",
        principal_id=sp_oid,
        scope=(
            f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/marketing-api"
        ),
    )
    kv_assignment = SimpleNamespace(
        name="ra-2",
        role_definition_id=(
            f"/subscriptions/{SUB}/providers/Microsoft.Authorization/"
            "roleDefinitions/kv-secrets-user"
        ),
        principal_type="ServicePrincipal",
        principal_id=sp_oid,
        scope=(
            f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/corp-kv"
        ),
    )

    role_defs = {
        assignment.role_definition_id: SimpleNamespace(role_name="Website Contributor"),
        kv_assignment.role_definition_id: SimpleNamespace(role_name="Key Vault Secrets User"),
    }

    class _Auth:
        role_definitions = MagicMock()
        role_definitions.get_by_id = lambda rid: role_defs[rid]
        role_assignments = MagicMock()
        role_assignments.list_for_subscription = lambda: [assignment, kv_assignment]

    class _Storage:
        storage_accounts = MagicMock()
        storage_accounts.list = lambda: [SimpleNamespace(name="corpartifactsdev")]

    class _Kv:
        vaults = MagicMock()
        vaults.list = lambda: [SimpleNamespace(name="corp-kv")]

    class _Web:
        web_apps = MagicMock()
        web_apps.list = lambda: [SimpleNamespace(name="marketing-api", kind="app")]

    class _Compute:
        virtual_machines = MagicMock()
        virtual_machines.list_all = lambda: []

    class _Automation:
        automation_account = MagicMock()
        automation_account.list = lambda: []

    class _Cred:
        def client(self, name):
            return {
                "authorization": _Auth(),
                "storage": _Storage(),
                "keyvault": _Kv(),
                "web": _Web(),
                "compute": _Compute(),
                "automation": _Automation(),
            }[name]

    ctx = EnumContext(
        credentials=_Cred(),
        session_id="azure-enum-test",
        scope=ScopeBoundary(
            CloudProvider.AZURE,
            SCOPE,
            "sub",
            {"subscription_id": SUB},
        ),
    )
    artifacts = list(AzureEntitlementEnumerator().enumerate(ctx))
    edges = [e for a in artifacts for e in a.edges]
    assert any(
        e.rel_type == "CONTROLS" and e.target_native_id == "WebApp:marketing-api" for e in edges
    )
    assert any(
        e.rel_type == "READS" and e.target_native_id == "KeyVault:corp-kv" for e in edges
    )
    assert not any("*" in (e.target_native_id or "") for e in edges)


def test_multi_hop_sp_webapp_mi_kv_path():
    """SP → CONTROLS WebApp → EXECUTES_AS MI → READS KV secret (≥3 hops)."""
    sp = "azure:serviceprincipal:sp-ci"
    mi = "azure:managedidentity:mi-web"
    web = "WebApp:api"
    secret = "KeyVaultSecret:kv/prod-pii"
    artifacts = [
        ConceptArtifact(
            ConceptType.IDENTITY,
            CloudProvider.AZURE,
            sp,
            SCOPE,
            {"is_caller": True, "display_name": "sp-ci"},
            Evidence("test", {}),
        ),
        ConceptArtifact(
            ConceptType.IDENTITY,
            CloudProvider.AZURE,
            mi,
            SCOPE,
            {"display_name": "mi-web"},
            Evidence("test", {}),
        ),
        ConceptArtifact(
            ConceptType.RUNTIME_BINDING,
            CloudProvider.AZURE,
            web,
            SCOPE,
            {"resource_type": "WebApp", "display_name": "api"},
            Evidence("test", {}),
            edges=[ConceptEdge("EXECUTES_AS", mi, ConceptType.IDENTITY)],
        ),
        ConceptArtifact(
            ConceptType.SECRET_STORE,
            CloudProvider.AZURE,
            secret,
            SCOPE,
            {
                "resource_type": "KeyVaultSecret",
                "display_name": "prod-pii",
                "is_high_value": True,
            },
            Evidence("test", {}),
            edges=[
                ConceptEdge("READS", secret, ConceptType.SECRET_STORE, src_native_id=mi),
            ],
        ),
        ConceptArtifact(
            ConceptType.ENTITLEMENT,
            CloudProvider.AZURE,
            "azure:roleassignment:web",
            SCOPE,
            {"role_name": "Website Contributor"},
            Evidence("test", {}),
            edges=[
                ConceptEdge(
                    "CONTROLS",
                    web,
                    ConceptType.RUNTIME_BINDING,
                    src_native_id=sp,
                )
            ],
        ),
    ]

    builder = GraphBuilder("azure-multihop")
    ConceptNormalizer().ingest(builder, artifacts)
    start = next(
        nid for nid, n in builder.snapshot.nodes.items() if n.props.get("native_id") == sp
    )
    end = next(
        nid for nid, n in builder.snapshot.nodes.items() if n.props.get("native_id") == secret
    )
    paths = find_attack_paths(builder.snapshot, start_node_id=start, end_node_id=end, max_depth=8)
    assert paths, "expected multi-hop path SP→WebApp→MI→secret"
    assert len(paths[0].steps) >= 3
    assert len(paths[0].node_ids) >= 4
    rels = {s.rel_type for s in paths[0].steps}
    assert "CONTROLS" in rels
    assert "READS" in rels
    assert "EXECUTES_AS" in rels or "CAN_ESCAPE_TO" in rels
