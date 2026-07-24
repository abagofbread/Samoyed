from __future__ import annotations

from samoyed.attack.cross_cloud_resolve import enrich_cross_cloud_resolve
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.cloud.providers import make_scope_id
from samoyed.graph.builder import GraphBuilder
from samoyed.network.session_graft import ensure_scope_boundary, find_session_for_scope
from samoyed.path_engine.search import find_attack_paths


class _FakeSession:
    def __init__(
        self,
        session_id: str,
        scope_id: str,
        provider: CloudProvider,
        *,
        build_snapshot=None,
        metadata: dict | None = None,
    ):
        self.session_id = session_id
        self.scope_id = scope_id
        self.provider = provider
        ident = scope_id.split(":")[-1]
        self.metadata = metadata or {
            "project_id": ident,
            "account_id": ident,
            "subscription_id": ident,
        }
        if build_snapshot is not None:
            self.snapshot = build_snapshot(session_id, scope_id)
        else:
            b = GraphBuilder(session_id)
            b.add_concept_node(
                concept_type=ConceptType.SECRET_STORE,
                native_id="GCPSecret:peer-secret",
                props={"display_name": "peer-secret", "project_id": ident},
            )
            self.snapshot = b.snapshot


class _FakeStore:
    def __init__(self, sessions):
        self._sessions = sessions

    def list_sessions(self):
        return list(self._sessions)

    def get(self, session_id: str):
        for s in self._sessions:
            if s.session_id == session_id:
                return s
        return None


def test_find_session_for_gcp_project_scope():
    scope = make_scope_id(CloudProvider.GCP, "project", "proj-pci")
    peer = _FakeSession("s-peer", scope, CloudProvider.GCP)
    store = _FakeStore([peer])
    assert find_session_for_scope(store, scope) is peer


def test_enrich_cross_cloud_stub_when_no_peer_session():
    builder = GraphBuilder("s-local")
    sa = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="gcp:serviceaccount:runner@proj-app.iam.gserviceaccount.com",
        props={
            "provider": "gcp",
            "project_id": "proj-app",
            "display_name": "runner",
        },
    )
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/FederatedAdmin",
        props={"provider": "aws", "account_id": "111111111111"},
    )
    builder.add_edge(
        src_id=sa,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=role,
        props={"mechanism": "wif"},
    )
    stats = enrich_cross_cloud_resolve(
        builder, session_store=_FakeStore([]), local_provider=CloudProvider.GCP
    )
    assert stats["cross_cloud_resolved"] >= 1
    assert stats["cross_cloud_stubs"] >= 1
    aws_scope = make_scope_id(CloudProvider.AWS, "account", "111111111111")
    boundary = ensure_scope_boundary(builder, aws_scope, stub=True)
    assert boundary in builder.snapshot.nodes


def test_azure_wif_stub_and_graft_multi_hop_jewel():
    aws_account = "999999999999"
    aws_scope = make_scope_id(CloudProvider.AWS, "account", aws_account)

    def build_peer(session_id: str, scope_id: str):
        b = GraphBuilder(session_id)
        role = b.add_concept_node(
            concept_type=ConceptType.IDENTITY,
            native_id=f"arn:aws:iam::{aws_account}:role/AzureFederatedDeploy",
            props={"provider": "aws", "account_id": aws_account, "display_name": "AzureFederatedDeploy"},
        )
        publisher = b.add_concept_node(
            concept_type=ConceptType.IDENTITY,
            native_id=f"arn:aws:iam::{aws_account}:role/ReleasePublisher",
            props={"provider": "aws", "account_id": aws_account},
        )
        jewel = b.add_concept_node(
            concept_type=ConceptType.SECRET_STORE,
            native_id=f"Secret:arn:aws:secretsmanager:us-east-1:{aws_account}:secret:prod/db/master",
            props={
                "provider": "aws",
                "account_id": aws_account,
                "display_name": "prod/db/master",
                "is_high_value": True,
            },
        )
        b.add_edge(src_id=role, rel_type="CAN_ASSUME_ROLE", dst_id=publisher, props={})
        b.add_edge(src_id=publisher, rel_type="READS", dst_id=jewel, props={})
        return b.snapshot

    peer = _FakeSession(
        "s-aws-peer",
        aws_scope,
        CloudProvider.AWS,
        build_snapshot=build_peer,
        metadata={"account_id": aws_account},
    )
    store = _FakeStore([peer])

    # No peer → stub
    stub_builder = GraphBuilder("s-azure-stub")
    mi = stub_builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="azure:managedidentity:8e8e8e8e-ffff-1111-2222-333333333333",
        props={
            "provider": "azure",
            "subscription_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        },
    )
    aws_role = stub_builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=f"arn:aws:iam::{aws_account}:role/AzureFederatedDeploy",
        props={"provider": "aws", "account_id": aws_account},
    )
    stub_builder.add_edge(
        src_id=mi,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=aws_role,
        props={"mechanism": "wif"},
    )
    stub_stats = enrich_cross_cloud_resolve(
        stub_builder, session_store=_FakeStore([]), local_provider=CloudProvider.AZURE
    )
    assert stub_stats["cross_cloud_stubs"] >= 1

    # Peer present → graft multi-node AWS session and reach jewel in ≥3 hops
    builder = GraphBuilder("s-azure-local")
    sp = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="azure:serviceprincipal:3f3f3f3f-aaaa-bbbb-cccc-dddddddddddd",
        props={
            "provider": "azure",
            "is_caller": True,
            "subscription_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        },
    )
    web = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="WebApp:release-api",
        props={"provider": "azure", "subscription_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
    )
    mi2 = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="azure:managedidentity:8e8e8e8e-ffff-1111-2222-333333333333",
        props={
            "provider": "azure",
            "subscription_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        },
    )
    role_dst = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=f"arn:aws:iam::{aws_account}:role/AzureFederatedDeploy",
        props={"provider": "aws", "account_id": aws_account},
    )
    builder.add_edge(src_id=sp, rel_type="CONTROLS", dst_id=web, props={})
    builder.add_edge(src_id=web, rel_type="EXECUTES_AS", dst_id=mi2, props={})
    builder.add_edge(
        src_id=mi2,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=role_dst,
        props={"mechanism": "wif"},
    )

    stats = enrich_cross_cloud_resolve(
        builder, session_store=store, local_provider=CloudProvider.AZURE
    )
    assert stats["cross_cloud_grafted"] >= 1
    natives = {n.props.get("native_id") for n in builder.snapshot.nodes.values()}
    assert f"Secret:arn:aws:secretsmanager:us-east-1:{aws_account}:secret:prod/db/master" in natives

    jewel = next(
        nid
        for nid, n in builder.snapshot.nodes.items()
        if n.props.get("native_id")
        == f"Secret:arn:aws:secretsmanager:us-east-1:{aws_account}:secret:prod/db/master"
    )
    paths = find_attack_paths(
        builder.snapshot, start_node_id=sp, end_node_id=jewel, max_depth=10
    )
    assert paths, "Azure start should reach grafted AWS jewel"
    assert len(paths[0].steps) >= 3
