from __future__ import annotations

from samoyed.attack.cross_cloud_resolve import enrich_cross_cloud_resolve
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.cloud.providers import make_scope_id
from samoyed.graph.builder import GraphBuilder
from samoyed.network.session_graft import ensure_scope_boundary, find_session_for_scope


class _FakeSession:
    def __init__(self, session_id: str, scope_id: str, provider: CloudProvider):
        self.session_id = session_id
        self.scope_id = scope_id
        self.provider = provider
        self.metadata = {"project_id": scope_id.split(":")[-1]}
        self.snapshot = GraphBuilder(session_id).snapshot
        b = GraphBuilder(session_id)
        nid = b.add_concept_node(
            concept_type=ConceptType.SECRET_STORE,
            native_id="GCPSecret:peer-secret",
            props={"display_name": "peer-secret", "project_id": scope_id.split(":")[-1]},
        )
        del nid
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
