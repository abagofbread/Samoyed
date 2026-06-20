from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from samoyed.cloud.artifacts import DenialLog, DenialRecord
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.protocol import CloudCredential, EnumContext
from samoyed.enumerators.registry import get_runner
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.neighbors import get_neighbors
from samoyed.graph.neo4j_store import (
    list_session_summaries,
    load_session_meta,
    load_snapshot,
    neo4j_configured,
    write_snapshot,
)
from samoyed.graph.persistence import (
    default_session_dir,
    read_session_file,
    snapshot_from_dict,
    snapshot_to_dict,
    write_session_file,
)
from samoyed.graph.sample import build_sample_graph, load_sample_session_metadata
from samoyed.graph.sample_k8s import build_sample_k8s_graph, load_sample_k8s_session_metadata
from samoyed.graph.sample_gcp import build_sample_gcp_graph, load_sample_gcp_session_metadata
from samoyed.graph.sample_azure import build_sample_azure_graph, load_sample_azure_session_metadata
from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.ingest.concept_normalizer import ConceptNormalizer
from samoyed.path_engine.explain import explain_path as build_path_explanation
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import find_attack_paths, get_blast_radius
from samoyed.probes.runner import probe_denial_log, probe_to_artifacts, run_api_probes
from samoyed.probes.scope import resolve_scope_best_effort
from samoyed.scenarios.k8s import CompromisedSaScenario, PodEscapeScenario
from samoyed.graph.sample_host import build_sample_host_graph, load_sample_host_session_metadata
from samoyed.scenarios.host_compromise import HostCompromiseScenario
from samoyed.scenarios.leaked_credential import LeakedCredentialScenario


@dataclass
class SessionRecord:
    session_id: str
    provider: CloudProvider
    caller_arn: str
    scope_id: str
    created_at: str
    status: str
    snapshot: GraphSnapshot
    denial_log: DenialLog = field(default_factory=DenialLog)
    metadata: dict[str, Any] = field(default_factory=dict)


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}

    def create_session(self, credentials: CloudCredential) -> SessionRecord:
        session_id = str(uuid.uuid4())
        scope = credentials.resolve_scope()
        caller_arn = scope.properties.get("arn") or scope.properties.get("native_id", "unknown")

        denial_log = DenialLog()
        ctx = EnumContext(
            credentials=credentials,
            session_id=session_id,
            scope=scope,
            denial_log=denial_log,
        )

        runner = get_runner(credentials.provider)
        artifacts = list(runner.run_all(ctx))

        builder = GraphBuilder(session_id)
        scope_node = builder.add_concept_node(
            concept_type=ConceptType.SCOPE_BOUNDARY,
            native_id=scope.scope_id,
            props={"display_name": scope.display_name, **scope.properties},
        )
        builder.link_session(scope_node)

        ConceptNormalizer().ingest(builder, artifacts)
        attack_edges = apply_attack_analysis(builder, provider=credentials.provider)

        metadata = {
            "artifact_count": len(artifacts),
            "node_count": len(builder.snapshot.nodes),
            "attack_patterns_matched": len(attack_edges),
        }
        record = SessionRecord(
            session_id=session_id,
            provider=credentials.provider,
            caller_arn=caller_arn,
            scope_id=scope.scope_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=builder.snapshot,
            denial_log=denial_log,
            metadata=metadata,
        )
        write_snapshot(builder.snapshot, session_meta=self._neo4j_meta(record))
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def create_probe_session(
        self,
        credentials: CloudCredential,
        *,
        high_value_only: bool = False,
        with_enum: bool = False,
    ) -> SessionRecord:
        """Build a session by probing API access (no IAM list permissions required)."""
        session_id = str(uuid.uuid4())
        scope = resolve_scope_best_effort(credentials)
        report = run_api_probes(credentials, high_value_only=high_value_only)
        caller_arn = report.caller_native_id

        denial_log = probe_denial_log(report)
        artifacts = probe_to_artifacts(report, scope)

        if with_enum:
            ctx = EnumContext(
                credentials=credentials,
                session_id=session_id,
                scope=scope,
                denial_log=denial_log,
            )
            try:
                runner = get_runner(credentials.provider)
                artifacts.extend(runner.run_all(ctx))
            except ValueError:
                pass

        builder = GraphBuilder(session_id)
        scope_node = builder.add_concept_node(
            concept_type=ConceptType.SCOPE_BOUNDARY,
            native_id=scope.scope_id,
            props={"display_name": scope.display_name, **scope.properties},
        )
        builder.link_session(scope_node)
        ConceptNormalizer().ingest(builder, artifacts)
        attack_edges = apply_attack_analysis(builder, provider=credentials.provider)

        metadata = {
            "artifact_count": len(artifacts),
            "node_count": len(builder.snapshot.nodes),
            "enumeration_mode": "probe",
            "probe_report": report.to_dict(),
            "allowed_operations": [r.operation for r in report.allowed],
            "attack_patterns_matched": len(attack_edges),
        }
        record = SessionRecord(
            session_id=session_id,
            provider=credentials.provider,
            caller_arn=caller_arn,
            scope_id=scope.scope_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=builder.snapshot,
            denial_log=denial_log,
            metadata=metadata,
        )
        write_snapshot(builder.snapshot, session_meta=self._neo4j_meta(record))
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def create_cartography_session(
        self,
        *,
        caller_arn: str | None = None,
        account_id: str | None = None,
        project_id: str | None = None,
        neo4j_uri: str | None = None,
        neo4j_user: str | None = None,
        neo4j_password: str | None = None,
        neo4j_database: str | None = None,
        provider: CloudProvider = CloudProvider.AWS,
    ) -> SessionRecord:
        """Import an existing Cartography Neo4j graph as a Samoyed attack-path session."""
        from samoyed.connectors.cartography.client import CartographyClient
        from samoyed.connectors.cartography.importer import import_cartography_graph

        session_id = str(uuid.uuid4())
        with CartographyClient(
            uri=neo4j_uri,
            user=neo4j_user,
            password=neo4j_password,
            database=neo4j_database,
        ) as client:
            if not client.ping():
                raise RuntimeError("Could not reach Cartography Neo4j database")
            builder, meta = import_cartography_graph(
                client,
                session_id=session_id,
                caller_arn=caller_arn,
                account_id=account_id,
                project_id=project_id,
                provider=provider,
            )

        resolved_caller = meta.get("caller_arn") or caller_arn or "cartography:import"
        record = SessionRecord(
            session_id=session_id,
            provider=provider,
            caller_arn=resolved_caller,
            scope_id=meta.get("cartography_account_id") or meta.get("cartography_project_id") or "cartography:scope",
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=builder.snapshot,
            denial_log=DenialLog(),
            metadata=meta,
        )
        write_snapshot(builder.snapshot, session_meta=self._neo4j_meta(record))
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def load_sample_session(self, session_id: str = "sample-lab") -> SessionRecord:
        snapshot = build_sample_graph(session_id)
        metadata = load_sample_session_metadata()
        record = SessionRecord(
            session_id=session_id,
            provider=CloudProvider.AWS,
            caller_arn=metadata["caller_arn"],
            scope_id=metadata["scope_id"],
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=snapshot,
            metadata=metadata,
        )
        write_snapshot(snapshot, session_meta=self._neo4j_meta(record))
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def load_sample_k8s_session(self, session_id: str = "sample-k8s") -> SessionRecord:
        snapshot = build_sample_k8s_graph(session_id)
        metadata = load_sample_k8s_session_metadata()
        record = SessionRecord(
            session_id=session_id,
            provider=CloudProvider.KUBERNETES,
            caller_arn=metadata["caller_arn"],
            scope_id=metadata["scope_id"],
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=snapshot,
            metadata=metadata,
        )
        write_snapshot(snapshot, session_meta=self._neo4j_meta(record))
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def load_sample_gcp_session(self, session_id: str = "sample-gcp") -> SessionRecord:
        snapshot = build_sample_gcp_graph(session_id)
        metadata = load_sample_gcp_session_metadata()
        record = SessionRecord(
            session_id=session_id,
            provider=CloudProvider.GCP,
            caller_arn=metadata["caller_arn"],
            scope_id=metadata["scope_id"],
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=snapshot,
            metadata=metadata,
        )
        write_snapshot(snapshot, session_meta=self._neo4j_meta(record))
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def load_sample_azure_session(self, session_id: str = "sample-azure") -> SessionRecord:
        snapshot = build_sample_azure_graph(session_id)
        metadata = load_sample_azure_session_metadata()
        record = SessionRecord(
            session_id=session_id,
            provider=CloudProvider.AZURE,
            caller_arn=metadata["caller_arn"],
            scope_id=metadata["scope_id"],
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=snapshot,
            metadata=metadata,
        )
        write_snapshot(snapshot, session_meta=self._neo4j_meta(record))
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def load_sample_host_session(self, session_id: str = "sample-host") -> SessionRecord:
        snapshot = build_sample_host_graph(session_id)
        metadata = load_sample_host_session_metadata()
        record = SessionRecord(
            session_id=session_id,
            provider=CloudProvider.AWS,
            caller_arn=metadata["caller_arn"],
            scope_id=metadata["scope_id"],
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=snapshot,
            metadata=metadata,
        )
        write_snapshot(snapshot, session_meta=self._neo4j_meta(record))
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def get(self, session_id: str) -> SessionRecord | None:
        cached = self._sessions.get(session_id)
        if cached:
            return cached
        record = self._load_from_disk(session_id)
        if record:
            self._sessions[session_id] = record
            return record
        snapshot = load_snapshot(session_id)
        if not snapshot:
            return None
        meta = load_session_meta(session_id) or {}
        denial_log = DenialLog()
        if meta.get("denial_log_json"):
            try:
                for item in json.loads(meta["denial_log_json"]):
                    denial_log.add(DenialRecord(**item))
            except (json.JSONDecodeError, TypeError):
                pass
        metadata = meta.get("metadata_json")
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        record = SessionRecord(
            session_id=session_id,
            provider=CloudProvider(meta.get("provider", "aws")),
            caller_arn=meta.get("caller_arn", "unknown"),
            scope_id=meta.get("scope_id", ""),
            created_at=meta.get("created_at", ""),
            status=meta.get("status", "complete"),
            snapshot=snapshot,
            denial_log=denial_log,
            metadata=metadata or {"node_count": len(snapshot.nodes)},
        )
        self._sessions[session_id] = record
        return record

    def list_sessions(self) -> list[SessionRecord]:
        seen = set(self._sessions.keys())
        records = list(self._sessions.values())
        session_dir = default_session_dir()
        if session_dir.is_dir():
            for path in sorted(session_dir.glob("*.json"), reverse=True):
                sid = path.stem
                if sid in seen:
                    continue
                loaded = self.get(sid)
                if loaded:
                    records.append(loaded)
                    seen.add(sid)
        if neo4j_configured():
            for summary in list_session_summaries():
                sid = summary["session_id"]
                if sid in seen:
                    continue
                loaded = self.get(sid)
                if loaded:
                    records.append(loaded)
                    seen.add(sid)
        return records

    def find_caller_node(self, session: SessionRecord) -> str | None:
        for node_id, node in session.snapshot.nodes.items():
            if node.props.get("is_caller"):
                return node_id
            if session.caller_arn and (
                node.props.get("arn") == session.caller_arn
                or node.props.get("native_id") == session.caller_arn
            ):
                return node_id
        return None

    def find_workload_node(self, session: SessionRecord, *, name: str | None = None) -> str | None:
        for node_id, node in session.snapshot.nodes.items():
            if node.props.get("concept_type") != ConceptType.WORKLOAD.value:
                continue
            if name and node.props.get("name") != name:
                continue
            return node_id
        return None

    def find_host_node(self, session: SessionRecord) -> str | None:
        for node_id, node in session.snapshot.nodes.items():
            if node.props.get("native_kind") == "CompromisedHost":
                return node_id
            if node.props.get("is_scenario_start") and node.props.get("pivot_surface") == "host":
                return node_id
        return None

    def run_scenario(self, session_id: str, name: str) -> list[PathResult]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        start = self.find_caller_node(session)
        if not start:
            raise ValueError("Caller node not found in graph")
        if name == "host-compromise":
            start = self.find_host_node(session) or start
            return HostCompromiseScenario().run(session.snapshot, start)
        if name == "leaked-credential":
            return LeakedCredentialScenario().run(session.snapshot, start)
        if name == "compromised-sa":
            return CompromisedSaScenario().run(session.snapshot, start)
        if name == "pod-escape":
            workload = self.find_workload_node(session, name="evil-pod") or start
            return PodEscapeScenario().run(session.snapshot, workload)
        raise ValueError(f"Unknown scenario: {name}")

    def query_paths(
        self,
        session_id: str,
        *,
        start_node_id: str | None = None,
        target_concept: str | None = None,
        target_resource_type: str | None = None,
        max_depth: int = 6,
    ) -> list[PathResult]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        start = start_node_id or self.find_caller_node(session)
        if not start:
            return []
        return find_attack_paths(
            session.snapshot,
            start_node_id=start,
            target_concept=target_concept,
            target_resource_type=target_resource_type,
            max_depth=max_depth,
        )

    def blast_radius(self, session_id: str, start_node_id: str | None = None) -> list[PathResult]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        start = start_node_id or self.find_caller_node(session)
        if not start:
            return []
        return get_blast_radius(session.snapshot, start_node_id=start)

    def get_neighbors(
        self,
        session_id: str,
        node_id: str,
        *,
        rel_type: str | None = None,
        direction: str = "out",
    ) -> list[dict[str, Any]]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        return get_neighbors(session.snapshot, node_id, rel_type=rel_type, direction=direction)  # type: ignore[arg-type]

    def explain_path(self, session_id: str, path_id: str) -> dict[str, Any]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        start = self.find_caller_node(session)
        if not start:
            raise ValueError("Caller node not found in graph")
        candidates = find_attack_paths(session.snapshot, start_node_id=start, max_depth=8, max_paths=50)
        candidates.extend(get_blast_radius(session.snapshot, start_node_id=start))
        for path in candidates:
            if path.path_id == path_id:
                return build_path_explanation(session.snapshot, path)
        raise ValueError(f"Path not found: {path_id}")

    def search_nodes(
        self,
        session_id: str,
        *,
        q: str = "",
        concept_type: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        results: list[dict[str, Any]] = []
        q_lower = q.lower()
        for node in session.snapshot.nodes.values():
            if node.label == "CollectionSession":
                continue
            if concept_type and node.props.get("concept_type") != concept_type:
                continue
            haystack = " ".join(
                str(node.props.get(k, ""))
                for k in ("native_id", "display_name", "arn", "name", "namespace", "concept_type")
            ).lower()
            haystack += f" {node.node_id.lower()} {node.label.lower()}"
            if q and q_lower not in haystack:
                continue
            results.append(
                {
                    "id": node.node_id,
                    "label": node.label,
                    "display": node.props.get("display_name")
                    or node.props.get("native_id")
                    or node.props.get("arn")
                    or node.node_id,
                    **node.props,
                }
            )
            if len(results) >= limit:
                break
        return results

    def update_node_properties(
        self,
        session_id: str,
        node_id: str,
        properties: dict[str, Any],
    ) -> dict[str, Any]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        node = session.snapshot.nodes.get(node_id)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        node.props.update(properties)
        self._persist(session)
        write_snapshot(session.snapshot, session_meta=self._neo4j_meta(session))
        return {"id": node.node_id, "label": node.label, **node.props}

    def resolve_start_node(self, session_id: str, start: str | None) -> str | None:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        if not start or start == "caller":
            return self.find_caller_node(session)
        if start == "host":
            return self.find_host_node(session) or self.find_caller_node(session)
        if start in session.snapshot.nodes:
            return start
        return None

    def _neo4j_meta(self, record: SessionRecord) -> dict[str, Any]:
        return {
            "session_id": record.session_id,
            "caller_arn": record.caller_arn,
            "scope_id": record.scope_id,
            "provider": record.provider.value,
            "created_at": record.created_at,
            "status": record.status,
            "metadata_json": json.dumps(record.metadata),
            "denial_log_json": json.dumps([d.__dict__ for d in record.denial_log.records]),
        }

    def _persist(self, record: SessionRecord) -> None:
        write_session_file(
            {
                "session_id": record.session_id,
                "provider": record.provider.value,
                "caller_arn": record.caller_arn,
                "scope_id": record.scope_id,
                "created_at": record.created_at,
                "status": record.status,
                "metadata": record.metadata,
                "denial_log": [d.__dict__ for d in record.denial_log.records],
                "graph": snapshot_to_dict(record.snapshot),
            }
        )

    def _load_from_disk(self, session_id: str) -> SessionRecord | None:
        data = read_session_file(session_id)
        if not data:
            return None
        denial_log = DenialLog()
        for item in data.get("denial_log", []):
            denial_log.add(DenialRecord(**item))
        return SessionRecord(
            session_id=data["session_id"],
            provider=CloudProvider(data.get("provider", "aws")),
            caller_arn=data.get("caller_arn", "unknown"),
            scope_id=data.get("scope_id", ""),
            created_at=data.get("created_at", ""),
            status=data.get("status", "complete"),
            snapshot=snapshot_from_dict(data["graph"]),
            denial_log=denial_log,
            metadata=data.get("metadata", {}),
        )


SESSION_STORE = SessionStore()
