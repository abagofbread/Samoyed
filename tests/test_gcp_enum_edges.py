from types import SimpleNamespace

from samoyed.cloud.concepts import CloudProvider
from samoyed.credentials.protocol import EnumContext, ScopeBoundary
from samoyed.enumerators.gcp import GcpEntitlementEnumerator


class _Iam:
    def list_service_accounts(self, *, request):
        assert request["parent"] == "projects/demo"
        return [SimpleNamespace(email="target@demo.iam.gserviceaccount.com", name="projects/demo/serviceAccounts/target@demo.iam.gserviceaccount.com")]

    def get_iam_policy(self, *, request):
        return SimpleNamespace(bindings=[])


class _ResourceManager:
    def get_iam_policy(self, *, request):
        return SimpleNamespace(
            bindings=[
                SimpleNamespace(
                    role="roles/iam.serviceAccountTokenCreator",
                    members=["serviceAccount:caller@demo.iam.gserviceaccount.com"],
                )
            ]
        )


class _Credential:
    def client(self, name):
        if name == "iam":
            return _Iam()
        if name == "resourcemanager":
            return _ResourceManager()
        raise ValueError(name)


def test_entitlement_expands_service_account_targets():
    ctx = EnumContext(
        credentials=_Credential(),
        session_id="test",
        scope=ScopeBoundary(CloudProvider.GCP, "gcp:project:demo", "demo", {"project_id": "demo"}),
    )
    artifacts = list(GcpEntitlementEnumerator().enumerate(ctx))
    edges = [edge for artifact in artifacts for edge in artifact.edges]
    assert any(
        edge.rel_type == "CAN_ASSUME_ROLE"
        and edge.target_native_id == "gcp:serviceaccount:target@demo.iam.gserviceaccount.com"
        for edge in edges
    )
    assert not any(edge.target_native_id == "gcp:serviceaccount:*" for edge in edges)
