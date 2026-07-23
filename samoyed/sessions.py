from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from samoyed.cloud.artifacts import DenialLog, DenialRecord
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.protocol import CloudCredential, EnumContext
from samoyed.enumerators.registry import get_runner
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot
from samoyed.graph.markings import (
    apply_marking,
    find_compromised_nodes,
    find_high_value_nodes,
    summarize_markings,
)
from samoyed.graph.relationships import (
    add_analyst_edge,
    list_declared_relationships,
    normalize_relationship,
    propagate_compromise,
    resolve_relationship_endpoints,
)
from samoyed.graph.neo4j_store import (
    delete_snapshot as neo4j_delete_snapshot,
    list_session_summaries as neo4j_list_session_summaries,
    load_session_meta,
    load_snapshot,
    neo4j_configured,
    write_snapshot,
)
from samoyed.graph import neo4j_query as neo4j_reads
from samoyed.graph.persistence import (
    default_session_dir,
    delete_session_file,
    read_session_file,
    snapshot_from_dict,
    snapshot_to_dict,
    write_session_file,
)
from samoyed.graph.refs import resolve_node_ref
from samoyed.graph.repair import repair_legacy_internet_exposure
from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.attack.surface import enrich_attack_surface
from samoyed.ingest.concept_normalizer import ConceptNormalizer
from samoyed.path_engine.explain import explain_path as build_path_explanation
from samoyed.path_engine.models import PathResult
from samoyed.path_engine.search import find_attack_paths, get_blast_radius
from samoyed.probes.runner import probe_denial_log, probe_to_artifacts, run_api_probes
from samoyed.probes.scope import resolve_scope_best_effort
from samoyed.scenarios.k8s import CompromisedSaScenario, PodEscapeScenario
from samoyed.scenarios.host_compromise import HostCompromiseScenario
from samoyed.scenarios.leaked_credential import LeakedCredentialScenario
from samoyed.scenarios.cross_account import CanReachOtherAccountsScenario
from samoyed.session_naming import (
    build_session_id,
    derive_short_name,
    extract_scope_key,
    parse_session_id,
    rebind_graph_session_id,
    session_short_name,
)


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

    def _existing_session_ids(self) -> set[str]:
        return {summary["session_id"] for summary in self._collect_session_summaries()}

    def _allocate_session_id(
        self,
        *,
        provider: CloudProvider,
        scope_id: str,
        caller_arn: str = "",
        metadata: dict[str, Any] | None = None,
        created_at: datetime | None = None,
        override: str | None = None,
    ) -> tuple[str, str, str]:
        if override:
            scope_key = extract_scope_key(provider, scope_id, caller_arn=caller_arn, metadata=metadata)
            short_name = derive_short_name(provider, scope_key)
            return override, short_name, scope_key

        created_at = created_at or datetime.now(timezone.utc)
        scope_key = extract_scope_key(provider, scope_id, caller_arn=caller_arn, metadata=metadata)
        short_name = derive_short_name(provider, scope_key)
        session_id = build_session_id(short_name, created_at, scope_key, self._existing_session_ids())
        return session_id, short_name, scope_key

    def resolve_session_ref(
        self,
        ref: str | None = None,
        *,
        include_demos: bool = False,
    ) -> SessionRecord | None:
        """Resolve full id, short name (most recent), or default to newest non-demo session."""
        if ref:
            exact = self.get(ref)
            if exact:
                return exact
            matches = self._session_ids_matching_ref(ref, include_demos=include_demos)
            if matches:
                return self.get(matches[0])
            return None

        summaries = self.list_session_summaries(
            scope="recent", limit=1, include_demos=include_demos
        )
        if not summaries:
            return None
        return self.get(summaries[0]["session_id"])

    def _session_ids_matching_ref(self, ref: str, *, include_demos: bool = False) -> list[str]:
        ref_lower = ref.strip().lower()
        summaries = self._sort_summaries_newest_first(self._collect_session_summaries())
        if not include_demos:
            summaries = [s for s in summaries if not s.get("is_demo")]

        matches: list[str] = []
        for summary in summaries:
            sid = summary["session_id"]
            meta = summary.get("metadata") or {}
            short = session_short_name(sid, meta)
            if sid == ref or sid.lower() == ref_lower:
                matches.append(sid)
            elif short and short.lower() == ref_lower:
                matches.append(sid)
            elif sid.startswith(f"{ref}_"):
                matches.append(sid)
        return matches

    def create_session(self, credentials: CloudCredential) -> SessionRecord:
        scope = credentials.resolve_scope()
        caller_arn = scope.properties.get("arn") or scope.properties.get("native_id", "unknown")
        created_at = datetime.now(timezone.utc)
        session_id, short_name, scope_key = self._allocate_session_id(
            provider=credentials.provider,
            scope_id=scope.scope_id,
            caller_arn=caller_arn,
            created_at=created_at,
        )

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
        enrich_attack_surface(builder, provider=credentials.provider)

        network_stats = None
        network_inventory = None
        if credentials.provider == CloudProvider.AWS:
            from samoyed.enumerators.aws.network import collect_aws_network_inventory
            from samoyed.network.enrich import enrich_network_reachability

            network_inventory = collect_aws_network_inventory(ctx)
            network_stats = enrich_network_reachability(
                builder,
                network_inventory,
                session_store=self,
                inventory_source="aws-enum",
            )

        metadata = {
            "artifact_count": len(artifacts),
            "node_count": len(builder.snapshot.nodes),
            "attack_patterns_matched": len(attack_edges),
            "short_name": short_name,
            "scope_key": scope_key,
            "network_enrichment": network_stats,
            "network_inventory": network_inventory.to_dict()
            if network_inventory and not network_inventory.is_empty()
            else None,
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
        scope = resolve_scope_best_effort(credentials)
        created_at = datetime.now(timezone.utc)
        session_id, short_name, scope_key = self._allocate_session_id(
            provider=credentials.provider,
            scope_id=scope.scope_id,
            caller_arn="",
            created_at=created_at,
        )
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
        enrich_attack_surface(builder, provider=credentials.provider)

        metadata = {
            "artifact_count": len(artifacts),
            "node_count": len(builder.snapshot.nodes),
            "enumeration_mode": "probe",
            "probe_report": report.to_dict(),
            "allowed_operations": [r.operation for r in report.allowed],
            "attack_patterns_matched": len(attack_edges),
            "short_name": short_name,
            "scope_key": scope_key,
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

        created_at = datetime.now(timezone.utc)
        with CartographyClient(
            uri=neo4j_uri,
            user=neo4j_user,
            password=neo4j_password,
            database=neo4j_database,
        ) as client:
            if not client.ping():
                raise RuntimeError("Could not reach Cartography Neo4j database")
            placeholder_id = "cartography-pending"
            builder, meta = import_cartography_graph(
                client,
                session_id=placeholder_id,
                caller_arn=caller_arn,
                account_id=account_id,
                project_id=project_id,
                provider=provider,
                session_store=self,
            )

        resolved_caller = meta.get("caller_arn") or caller_arn or "cartography:import"
        scope_id = meta.get("cartography_account_id") or meta.get("cartography_project_id") or "cartography:scope"
        session_id, short_name, scope_key = self._allocate_session_id(
            provider=provider,
            scope_id=str(scope_id),
            caller_arn=resolved_caller,
            metadata=meta,
            created_at=created_at,
        )
        rebind_graph_session_id(builder.snapshot, "cartography-pending", session_id)
        meta["short_name"] = short_name
        meta["scope_key"] = scope_key
        record = SessionRecord(
            session_id=session_id,
            provider=provider,
            caller_arn=resolved_caller,
            scope_id=str(scope_id),
            created_at=datetime.now(timezone.utc).isoformat(),
            status="complete",
            snapshot=builder.snapshot,
            denial_log=DenialLog(),
            metadata=meta,
        )
        self._persist(record)
        self._sessions[session_id] = record
        return record

    def load_fixture(self, fixture_id: str, session_id: str | None = None) -> SessionRecord:
        """Import a bundled field report (iam-report, cloudfox, aws-authz) via connector pipeline."""
        from samoyed.fixtures.loader import load_fixture_session

        return load_fixture_session(fixture_id, session_id=session_id)

    def create_import_session(
        self,
        connector_id: str,
        payload: bytes | str,
        *,
        caller_arn: str | None = None,
        session_id: str | None = None,
        graph_role: str | None = None,
        graph_access: str | None = None,
        persist: bool = True,
    ) -> SessionRecord:
        from samoyed.connectors.registry import import_report

        builder, meta = import_report(
            connector_id,
            payload,
            session_id="import-pending",
            caller_arn=caller_arn,
            session_store=self,
        )
        resolved_caller = meta.get("caller_arn") or caller_arn or f"{connector_id}:import"
        scope_id = next(
            (
                node.props.get("native_id")
                for node in builder.snapshot.nodes.values()
                if node.props.get("concept_type") == ConceptType.SCOPE_BOUNDARY.value
            ),
            f"import:{connector_id}",
        )
        meta.setdefault("source", connector_id)
        meta["caller_arn"] = resolved_caller
        provider = CloudProvider(meta.get("provider", "aws"))
        created_at = datetime.now(timezone.utc)
        sid, short_name, scope_key = self._allocate_session_id(
            provider=provider,
            scope_id=str(scope_id),
            caller_arn=resolved_caller,
            metadata=meta,
            created_at=created_at,
            override=session_id,
        )
        rebind_graph_session_id(builder.snapshot, "import-pending", sid)
        meta["short_name"] = short_name
        meta["scope_key"] = scope_key
        if graph_role:
            meta["graph_role"] = graph_role
        if graph_access:
            meta["graph_access"] = graph_access
        record = SessionRecord(
            session_id=sid,
            provider=provider,
            caller_arn=resolved_caller,
            scope_id=str(scope_id),
            created_at=created_at.isoformat(),
            status="complete",
            snapshot=builder.snapshot,
            denial_log=DenialLog(),
            metadata=meta,
        )
        if persist:
            self._persist(record)
        self._sessions[sid] = record
        return record

    def set_session_graph_role(
        self,
        session_id: str,
        *,
        graph_role: str | None = None,
        graph_access: str | None = None,
    ) -> dict[str, Any]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        if graph_role is not None:
            session.metadata["graph_role"] = graph_role
        if graph_access is not None:
            session.metadata["graph_access"] = graph_access
        self._persist(session)
        return {
            "session_id": session_id,
            "graph_role": session.metadata.get("graph_role"),
            "graph_access": session.metadata.get("graph_access"),
        }

    def attach_network_inventory(
        self,
        session_id: str,
        payload: bytes | str | dict[str, Any],
        *,
        connector_id: str = "network-inventory",
    ) -> dict[str, Any]:
        """Merge NetworkInventory (or terraform tfstate) into an existing session graph."""
        from samoyed.connectors.network_inventory.importer import attach_network_inventory_to_builder
        from samoyed.connectors.terraform.importer import parse_tfstate_to_inventory
        from samoyed.connectors._shared import parse_json_payload
        from samoyed.network.enrich import enrich_network_reachability
        from samoyed.network.model import NetworkInventory

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        builder = GraphBuilder(session_id)
        builder.snapshot = session.snapshot

        if connector_id == "terraform":
            data = payload if isinstance(payload, dict) else parse_json_payload(payload)
            inventory = parse_tfstate_to_inventory(data if isinstance(data, dict) else {})
            stats = enrich_network_reachability(
                builder,
                inventory,
                session_store=self,
                inventory_source="terraform",
            )
            result = {"network_enrichment": stats, "network_inventory": inventory.to_dict()}
        else:
            result = attach_network_inventory_to_builder(builder, payload, session_store=self)

        session.metadata["network_enrichment"] = result.get("network_enrichment")
        if result.get("network_inventory"):
            prev = session.metadata.get("network_inventory")
            merged = NetworkInventory.from_dict(prev).merge(
                NetworkInventory.from_dict(result["network_inventory"])
            )
            session.metadata["network_inventory"] = merged.to_dict()
        session.metadata["node_count"] = len(session.snapshot.nodes)
        self._persist(session)
        write_snapshot(session.snapshot, session_meta=self._neo4j_meta(session))
        return {"session_id": session_id, **result}

    def graph_payload(
        self,
        session_id: str,
        *,
        detail: str = "full",
        allow_restricted: bool = False,
    ) -> dict[str, Any]:
        from samoyed.graph.access import filter_graph_payload, graph_access_for_metadata

        from samoyed.attack.surface import blast_graph_changed, repair_blast_graph
        from samoyed.enrichment.labels import relabel_pivot_materials
        from samoyed.graph.builder import GraphBuilder

        # Summary / compare-only can answer from Neo4j without hydrating the snapshot.
        if detail == "summary" and neo4j_configured():
            summary = neo4j_reads.graph_summary(session_id)
            if summary is not None:
                return {"access": "summary", **summary}

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        dirty = False
        if relabel_pivot_materials(session.snapshot):
            dirty = True
        # Global influence wiring on load (UNLOCKS, Secret:*, capability-glob, FEEDS)
        # so sessions don't require a separate "Enrich session" click after enum/import.
        builder = GraphBuilder(session.session_id)
        builder.snapshot = session.snapshot
        repair_stats = repair_blast_graph(builder)
        if blast_graph_changed(repair_stats):
            dirty = True
        if dirty:
            try:
                self._persist(session)
            except Exception:
                pass
        access = graph_access_for_metadata(session.metadata)
        if detail == "summary":
            access = "summary"
        elif allow_restricted and access == "compare_only":
            access = "full"
        if access in {"summary", "compare_only"} and neo4j_configured():
            summary = neo4j_reads.graph_summary(session_id)
            if summary is not None:
                if access == "summary":
                    return {"access": "summary", **summary}
                return {
                    "access": "compare_only",
                    "message": "Full graph withheld — use POST /api/sessions/compare for attack-surface diff.",
                    **summary,
                }
        return filter_graph_payload(session.snapshot, access=access)

    def compare_sessions(
        self,
        baseline_ref: str,
        proposed_ref: str,
        *,
        context_principal: str | None = None,
        max_depth: int = 10,
        max_paths: int = 40,
    ) -> dict[str, Any]:
        from samoyed.change_impact import compare_attack_surfaces

        baseline = self.resolve_session_ref(baseline_ref)
        proposed = self.resolve_session_ref(proposed_ref)
        if not baseline:
            raise KeyError(f"baseline session not found: {baseline_ref}")
        if not proposed:
            raise KeyError(f"proposed session not found: {proposed_ref}")

        principal = context_principal or baseline.caller_arn or "caller"
        if principal in {"caller", "start"}:
            principal = self.find_caller_node(baseline) or principal

        result = compare_attack_surfaces(
            baseline.snapshot,
            proposed.snapshot,
            provider=baseline.provider,
            context_principal=principal,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        return result.to_dict()

    def get(self, session_id: str) -> SessionRecord | None:
        cached = self._sessions.get(session_id)
        if cached:
            self._repair_loaded_session(cached)
            return cached
        # When Neo4j is configured it is the durable source of truth; JSON is a cache.
        if neo4j_configured():
            record = self._load_from_neo4j(session_id)
            if record:
                self._repair_loaded_session(record)
                self._sessions[session_id] = record
                return record
            record = self._load_from_disk(session_id)
            if record:
                # Hydrate Neo4j from legacy JSON sessions.
                self._repair_loaded_session(record)
                write_snapshot(record.snapshot, session_meta=self._neo4j_meta(record))
                self._sessions[session_id] = record
                return record
            return None
        record = self._load_from_disk(session_id)
        if record:
            self._repair_loaded_session(record)
            self._sessions[session_id] = record
            return record
        return None

    def _repair_loaded_session(self, record: SessionRecord) -> None:
        stats = repair_legacy_internet_exposure(record.snapshot)
        repaired = bool(stats["removed_nodes"])
        if repaired:
            record.metadata["node_count"] = len(record.snapshot.nodes)
            record.metadata["legacy_network_exposure_repair"] = stats
            self._persist(record)

        needs_neo4j_sync = bool(record.metadata.get("legacy_network_exposure_repair")) and not (
            record.metadata.get("legacy_network_exposure_repair_synced_neo4j")
        )
        if neo4j_configured() and (repaired or needs_neo4j_sync):
            neo4j_delete_snapshot(record.session_id)
            write_snapshot(record.snapshot, session_meta=self._neo4j_meta(record))
            record.metadata["legacy_network_exposure_repair_synced_neo4j"] = True
            self._persist(record)

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
            for summary in neo4j_list_session_summaries():
                sid = summary["session_id"]
                if sid in seen:
                    continue
                loaded = self.get(sid)
                if loaded:
                    records.append(loaded)
                    seen.add(sid)
        return records

    def list_session_summaries(
        self,
        *,
        scope: str = "recent",
        limit: int = 1,
        include_demos: bool = False,
        session_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        summaries = self._collect_session_summaries()
        if scope == "ids":
            if not session_ids:
                return []
            wanted: set[str] = set()
            for ref in session_ids:
                resolved = self.resolve_session_ref(ref, include_demos=include_demos)
                if resolved:
                    wanted.add(resolved.session_id)
                else:
                    wanted.add(ref)
            summaries = [s for s in summaries if s["session_id"] in wanted]
        elif not include_demos:
            summaries = [s for s in summaries if not s.get("is_demo")]

        summaries = self._sort_summaries_newest_first(summaries)

        if scope == "recent":
            return summaries[:limit]
        if scope == "all":
            return summaries[:limit] if limit else summaries
        return summaries

    def delete_session(self, session_ref: str, *, allow_demo: bool = False) -> dict[str, Any]:
        """Delete one session from memory, disk, and Neo4j."""
        record = self.resolve_session_ref(session_ref, include_demos=True)
        session_id = record.session_id if record else session_ref
        metadata = record.metadata if record else {}
        if not record:
            disk = read_session_file(session_ref)
            if disk:
                session_id = disk["session_id"]
                metadata = disk.get("metadata") or {}
            else:
                raise KeyError(session_ref)

        if not allow_demo and is_demo_session(session_id, metadata):
            raise ValueError(f"Refusing to delete demo/fixture session {session_id}")

        self._sessions.pop(session_id, None)
        removed_file = delete_session_file(session_id)
        removed_neo4j = neo4j_delete_snapshot(session_id)
        return {
            "session_id": session_id,
            "deleted": removed_file or record is not None or removed_neo4j,
            "removed_file": removed_file,
            "removed_neo4j": removed_neo4j,
        }

    def clear_sessions(self, *, include_demos: bool = False) -> dict[str, Any]:
        """Delete persisted attack-graph sessions. Demo/fixture sessions are kept unless requested."""
        session_ids: set[str] = set(self._sessions.keys())
        session_dir = default_session_dir()
        if session_dir.is_dir():
            session_ids.update(path.stem for path in session_dir.glob("*.json"))
        for summary in self._collect_session_summaries():
            session_ids.add(summary["session_id"])

        deleted: list[str] = []
        skipped: list[str] = []
        for session_id in sorted(session_ids):
            record = self.get(session_id)
            metadata = record.metadata if record else {}
            if not metadata:
                disk = read_session_file(session_id)
                metadata = (disk or {}).get("metadata") or {}
            if not include_demos and is_demo_session(session_id, metadata):
                skipped.append(session_id)
                continue
            try:
                result = self.delete_session(session_id, allow_demo=include_demos)
                if result["deleted"]:
                    deleted.append(session_id)
            except KeyError:
                continue
        return {
            "deleted_count": len(deleted),
            "deleted": deleted,
            "skipped_count": len(skipped),
            "skipped": skipped,
        }

    def _collect_session_summaries(self) -> list[dict[str, Any]]:
        seen: set[str] = set()
        summaries: list[dict[str, Any]] = []
        for record in self._sessions.values():
            seen.add(record.session_id)
            summaries.append(self._session_summary(record))
        session_dir = default_session_dir()
        if session_dir.is_dir():
            for path in sorted(session_dir.glob("*.json"), reverse=True):
                sid = path.stem
                if sid in seen:
                    continue
                summary = self._summary_from_session_file(path)
                if summary:
                    summaries.append(summary)
                    seen.add(sid)
        if neo4j_configured():
            for summary in neo4j_list_session_summaries():
                sid = summary["session_id"]
                if sid in seen:
                    continue
                meta = summary.get("metadata_json")
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except json.JSONDecodeError:
                        meta = {}
                summaries.append(
                    self._enrich_summary(
                        {
                            "session_id": sid,
                            "caller_arn": summary.get("caller_arn", "unknown"),
                            "created_at": summary.get("created_at", ""),
                            "status": summary.get("status", "complete"),
                            "provider": summary.get("provider", "aws"),
                            "metadata": meta or {},
                        }
                    )
                )
                seen.add(sid)
        return summaries

    @staticmethod
    def _sort_summaries_newest_first(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(summaries, key=lambda s: s.get("created_at") or "", reverse=True)

    @staticmethod
    def _enrich_summary(summary: dict[str, Any]) -> dict[str, Any]:
        sid = summary["session_id"]
        meta = summary.get("metadata") or {}
        summary["is_demo"] = is_demo_session(sid, meta)
        summary["short_name"] = session_short_name(sid, meta)
        parsed = parse_session_id(sid)
        summary["scope_key"] = meta.get("scope_key") or (parsed or {}).get("scope_key")
        return summary

    def run_graph_query(
        self,
        session_id: str,
        *,
        start_node_id: str | None = None,
        mode: str = "paths",
        target_concept: str | None = None,
        target_resource_type: str | None = None,
        end_node_id: str | None = None,
        end_id_contains: str | None = None,
        rel_types: list[str] | None = None,
        max_depth: int = 6,
        max_paths: int = 20,
        exclude_node_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        from samoyed.graph.backend import resolve_graph_backend
        from samoyed.path_engine.custom_query import run_graph_query

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)

        # Blast enrichment must run (and persist) before any Neo4j short-circuit,
        # otherwise Secret:*/FEEDS/capability-glob never land on the durable graph.
        if mode == "blast":
            from samoyed.attack.surface import blast_graph_changed, repair_blast_graph
            from samoyed.graph.builder import GraphBuilder

            builder = GraphBuilder(session.session_id)
            builder.snapshot = session.snapshot
            if blast_graph_changed(repair_blast_graph(builder)):
                try:
                    self._persist(session)
                except Exception:
                    pass

        backend = resolve_graph_backend()
        start = start_node_id or self.find_caller_node(session)
        if backend == "neo4j" and start and mode in {"paths", "blast", "neighbors"}:
            try:
                return run_graph_query(
                    None,
                    session_id=session_id,
                    start_node_id=start,
                    mode=mode,
                    target_concept=target_concept,
                    target_resource_type=target_resource_type,
                    end_node_id=end_node_id,
                    end_id_contains=end_id_contains,
                    rel_types=rel_types,
                    max_depth=max_depth,
                    max_paths=max_paths,
                    exclude_node_ids=exclude_node_ids,
                    backend="neo4j",
                )
            except Exception:
                pass

        if not start:
            raise ValueError("Start node not found")
        return run_graph_query(
            session.snapshot,
            session_id=session_id,
            start_node_id=start,
            mode=mode,
            target_concept=target_concept,
            target_resource_type=target_resource_type,
            end_node_id=end_node_id,
            end_id_contains=end_id_contains,
            rel_types=rel_types,
            max_depth=max_depth,
            max_paths=max_paths,
            exclude_node_ids=exclude_node_ids,
            backend=backend,
        )

    def analyze_proposed_changes(
        self,
        session_id: str,
        changes: list[dict[str, Any]],
        *,
        context_principal: str | None = None,
        max_depth: int = 8,
    ) -> dict[str, Any]:
        from samoyed.change_impact import analyze_proposed_changes

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        principal = context_principal or session.caller_arn or "caller"
        if principal in {"caller", "start"}:
            principal = self.find_caller_node(session) or principal
        result = analyze_proposed_changes(
            session.snapshot,
            changes,
            provider=session.provider,
            context_principal=principal,
            max_depth=max_depth,
        )
        return result.to_dict()

    def check_policy_access(
        self,
        session_id: str,
        *,
        principal: str,
        target: str,
        action: str | None = None,
    ) -> dict[str, Any]:
        from samoyed.policy.access import can_principal_access_node, principal_has_crypto_mining_risk

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        resolved_principal = principal
        if principal in {"caller", "start"}:
            resolved_principal = self.find_caller_node(session) or principal
        access = can_principal_access_node(
            session.snapshot,
            resolved_principal,
            target,
            action=action,
        )
        mining = principal_has_crypto_mining_risk(session.snapshot, resolved_principal)
        return {"access": access, "crypto_mining_risk": mining}

    def run_marking_paths_query(
        self,
        session_id: str,
        *,
        kind: str,
        max_depth: int = 6,
        max_paths: int = 30,
        exclude_node_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        from samoyed.path_engine.custom_query import serialize_paths
        from samoyed.path_engine.search import (
            find_compromised_to_high_value_paths,
            find_paths_to_high_value_nodes,
            get_blast_radius_multi,
        )
        from samoyed.graph.markings import find_compromised_nodes, find_high_value_nodes, summarize_markings

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)

        graph = session.snapshot
        markings = summarize_markings(graph)
        compromised_ids = find_compromised_nodes(graph)
        high_value_ids = find_high_value_nodes(graph)
        excluded = set(exclude_node_ids or ()) or None

        if kind == "compromised_to_high_value":
            paths = find_compromised_to_high_value_paths(
                graph, max_depth=max_depth, max_paths=max_paths, exclude_node_ids=excluded
            )
        elif kind == "blast_compromised":
            paths = get_blast_radius_multi(
                graph,
                start_node_ids=compromised_ids,
                max_depth=max_depth,
                max_paths=max_paths,
                exclude_node_ids=excluded,
            )
        elif kind == "to_high_value":
            paths = find_paths_to_high_value_nodes(
                graph,
                start_node_ids=compromised_ids,
                max_depth=max_depth,
                max_paths=max_paths,
                exclude_node_ids=excluded,
            )
        else:
            raise ValueError(
                f"Unknown marking query kind '{kind}'. "
                "Use compromised_to_high_value, blast_compromised, or to_high_value."
            )

        return {
            "kind": kind,
            "markings": markings,
            "compromised_starts": compromised_ids,
            "high_value_targets": high_value_ids,
            "paths": serialize_paths(paths),
        }

    @staticmethod
    def _session_summary(record: SessionRecord) -> dict[str, Any]:
        return SessionStore._enrich_summary(
            {
                "session_id": record.session_id,
                "caller_arn": record.caller_arn,
                "created_at": record.created_at,
                "status": record.status,
                "provider": record.provider.value,
                "metadata": record.metadata,
            }
        )

    @staticmethod
    def _summary_from_session_file(path: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        metadata = dict(data.get("metadata") or {})
        graph = data.get("graph") or {}
        if "node_count" not in metadata:
            metadata["node_count"] = len(graph.get("nodes", []))
        return SessionStore._enrich_summary(
            {
                "session_id": data.get("session_id", path.stem),
                "caller_arn": data.get("caller_arn", "unknown"),
                "created_at": data.get("created_at", ""),
                "status": data.get("status", "complete"),
                "provider": data.get("provider", "aws"),
                "metadata": metadata,
            }
        )

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

    def run_scenario(
        self,
        session_id: str,
        name: str,
        *,
        start_node_id: str | None = None,
    ) -> list[PathResult]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        start = start_node_id or self.find_caller_node(session)
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
        if name == "can-reach-other-accounts":
            start = self.find_caller_node(session) or self._resolve_compromised_start(session) or start
            return CanReachOtherAccountsScenario().run(session.snapshot, start)
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

    def blast_radius(
        self,
        session_id: str,
        start_node_id: str | None = None,
        *,
        max_depth: int = 6,
    ) -> list[PathResult]:
        from samoyed.attack.surface import blast_graph_changed, repair_blast_graph
        from samoyed.graph.builder import GraphBuilder

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        builder = GraphBuilder(session.session_id)
        builder.snapshot = session.snapshot
        if blast_graph_changed(repair_blast_graph(builder)):
            try:
                self._persist(session)
            except Exception:
                pass
        start = start_node_id or self.find_caller_node(session)
        if not start:
            return []
        return get_blast_radius(session.snapshot, start_node_id=start, max_depth=max_depth)

    def get_neighbors(
        self,
        session_id: str,
        node_id: str,
        *,
        rel_type: str | None = None,
        direction: str = "out",
    ) -> list[dict[str, Any]]:
        if neo4j_configured():
            neo = neo4j_reads.get_neighbors(
                session_id, node_id, rel_type=rel_type, direction=direction  # type: ignore[arg-type]
            )
            if neo is not None:
                return neo
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
        if neo4j_configured():
            neo = neo4j_reads.search_nodes(
                session_id, q=q, concept_type=concept_type, limit=limit
            )
            if neo is not None:
                return neo
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
        return {"id": node.node_id, "label": node.label, **node.props}

    def apply_enrichment(
        self,
        session_id: str,
        payload: bytes | str | dict[str, Any],
        *,
        target_node_id: str | None = None,
    ) -> dict[str, Any]:
        from samoyed.enrichment.apply import apply_enrichment_report
        from samoyed.graph.builder import GraphBuilder

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        builder = GraphBuilder(session.session_id)
        builder.snapshot = session.snapshot
        stats = apply_enrichment_report(
            builder,
            payload,
            default_target_node_id=target_node_id,
        )
        # Propagate derived edges/props across the whole graph (globs, FEEDS, …).
        surface = enrich_attack_surface(builder, provider=session.provider)
        stats["surface"] = surface
        session.snapshot = builder.snapshot
        session.metadata.setdefault("enrichment_runs", []).append(stats)
        self._persist(session)
        return stats

    def enrich_session_surface(self, session_id: str) -> dict[str, Any]:
        """Re-run attack-surface enrichment on an existing session (no collector file)."""
        from samoyed.enrichment.impact import repair_credential_impact
        from samoyed.enrichment.labels import relabel_pivot_materials
        from samoyed.graph.builder import GraphBuilder

        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        builder = GraphBuilder(session.session_id)
        builder.snapshot = session.snapshot
        relabeled = relabel_pivot_materials(session.snapshot)
        impact = repair_credential_impact(builder)
        surface = enrich_attack_surface(builder, provider=session.provider)
        session.snapshot = builder.snapshot
        stats = {
            "materials_relabeled": int(relabeled or 0),
            "credential_unlocks": int(impact.get("unlocks_applied") or 0),
            "credential_projected": int(impact.get("projected") or 0),
            **surface,
        }
        session.metadata.setdefault("enrichment_runs", []).append(
            {"kind": "session-surface", **stats}
        )
        self._persist(session)
        return stats

    def resolve_start_node(self, session_id: str, start: str | None) -> str | None:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        if not start or start == "caller":
            caller = self.find_caller_node(session)
            if caller:
                return caller
            host = self.find_host_node(session)
            if host:
                return host
            return self._fallback_start_node(session)
        if start == "host":
            return self.find_host_node(session) or self.find_caller_node(session)
        if start in {"compromised", "compromised_start"}:
            return self._resolve_compromised_start(session)

        # Same fuzzy resolver as enrichment name_hints / mark refs.
        return resolve_node_ref(session.snapshot, start)

    def resolve_end_node(self, session_id: str, end: str | None) -> str | None:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        if not end:
            return None
        if end in {"high_value", "crown_jewel", "crown-jewel", "crown_jewels"}:
            marked = find_high_value_nodes(session.snapshot)
            if len(marked) == 1:
                return marked[0]
            return None
        if end in {"caller", "host", "compromised", "compromised_start"}:
            return self.resolve_start_node(session_id, end)
        return resolve_node_ref(session.snapshot, end)

    def _resolve_compromised_start(self, session: SessionRecord) -> str | None:
        marked = find_compromised_nodes(session.snapshot)
        if not marked:
            return self.find_caller_node(session)
        if len(marked) == 1:
            return marked[0]
        caller = self.find_caller_node(session)
        if caller and caller in marked:
            return caller
        return marked[0]

    def _fallback_start_node(self, session: SessionRecord) -> str | None:
        """Pick a reasonable default when no caller/host is tagged."""
        for node_id, node in session.snapshot.nodes.items():
            if node.label == "CollectionSession":
                continue
            if node.props.get("is_scenario_start"):
                return node_id
        for node_id, node in session.snapshot.nodes.items():
            if node.label != "CollectionSession":
                return node_id
        return None

    def resolve_node_refs(self, session_id: str, refs: list[str]) -> tuple[list[str], list[str]]:
        resolved: list[str] = []
        unresolved: list[str] = []
        seen: set[str] = set()
        for ref in refs:
            ref = ref.strip()
            if not ref:
                continue
            node_id = self.resolve_start_node(session_id, ref)
            if node_id and node_id not in seen:
                resolved.append(node_id)
                seen.add(node_id)
            else:
                unresolved.append(ref)
        return resolved, unresolved

    def mark_nodes(
        self,
        session_id: str,
        refs: list[str],
        *,
        compromised: bool | None = None,
        high_value: bool | None = None,
        source: str = "analyst",
        clear: bool = False,
        mechanism: str | None = None,
    ) -> dict[str, Any]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        if compromised is None and high_value is None and mechanism is None:
            raise ValueError("Specify compromised, high_value, and/or mechanism")

        node_ids, unresolved = self.resolve_node_refs(session_id, refs)
        marked: list[dict[str, Any]] = []
        for node_id in node_ids:
            node = session.snapshot.nodes[node_id]
            apply_marking(
                node.props,
                compromised=compromised,
                high_value=high_value,
                source=source,
                clear=clear,
                mechanism=mechanism,
            )
            marked.append(
                {
                    "node_id": node_id,
                    "display": node.props.get("display_name")
                    or node.props.get("native_id")
                    or node_id,
                    "is_compromised": bool(node.props.get("is_compromised")),
                    "is_high_value": bool(node.props.get("is_high_value")),
                    "compromise_mechanism": node.props.get("compromise_mechanism"),
                }
            )
        if marked:
            self._persist(session)
        result = {
            "session_id": session_id,
            "marked": marked,
            "unresolved": unresolved,
        }
        if compromised and marked:
            propagated = propagate_compromise(session.snapshot)
            if propagated:
                self._persist(session)
                result["propagated"] = propagated
        return result

    def declare_relationship(
        self,
        session_id: str,
        *,
        relationship: str = "depends_on",
        from_ref: str | None = None,
        to_ref: str | None = None,
        supplier: str | None = None,
        consumer: str | None = None,
        dependent: str | None = None,
        dependency: str | None = None,
        compromise_flow: str = "downstream",
        source: str = "analyst",
        notes: str = "",
        propagate: bool = True,
    ) -> dict[str, Any]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)

        spec = normalize_relationship(relationship)
        flow = compromise_flow or spec.get("compromise_flow", "downstream")
        raw_from, raw_to = resolve_relationship_endpoints(
            spec,
            supplier=supplier,
            consumer=consumer,
            dependent=dependent,
            dependency=dependency,
            from_ref=from_ref,
            to_ref=to_ref,
        )
        src_ids, unresolved_from = self.resolve_node_refs(session_id, [raw_from])
        dst_ids, unresolved_to = self.resolve_node_refs(session_id, [raw_to])
        unresolved = unresolved_from + unresolved_to
        if not src_ids or not dst_ids:
            raise ValueError(f"Could not resolve relationship endpoints: {unresolved}")

        edge = add_analyst_edge(
            session.snapshot,
            src_id=src_ids[0],
            dst_id=dst_ids[0],
            rel_type=spec["rel_type"],
            source=source,
            notes=notes,
            relationship=relationship,
            compromise_flow=flow,  # type: ignore[arg-type]
        )
        result: dict[str, Any] = {
            "session_id": session_id,
            "relationship": relationship,
            "rel_type": spec["rel_type"],
            "compromise_flow": flow,
            "description": spec.get("description"),
            "dependent_id": edge.src_id,
            "dependency_id": edge.dst_id,
            "edge": {
                "dependent_id": edge.src_id,
                "rel": edge.rel_type,
                "dependency_id": edge.dst_id,
                "props": edge.props,
            },
            "unresolved": unresolved,
        }
        if propagate:
            propagated = propagate_compromise(session.snapshot)
            if propagated:
                result["propagated"] = propagated
        self._persist(session)
        return result

    def propagate_compromise(self, session_id: str) -> dict[str, Any]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        propagated = propagate_compromise(session.snapshot)
        if propagated:
            self._persist(session)
        return {"session_id": session_id, "propagated": propagated}

    def list_relationships(self, session_id: str) -> dict[str, Any]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        return {
            "session_id": session_id,
            "relationships": list_declared_relationships(session.snapshot),
        }

    def mark_from_alert(
        self,
        session_id: str,
        *,
        compromised_refs: list[str] | None = None,
        high_value_refs: list[str] | None = None,
        source: str = "alert",
    ) -> dict[str, Any]:
        results: dict[str, Any] = {"session_id": session_id, "compromised": None, "high_value": None}
        if compromised_refs:
            results["compromised"] = self.mark_nodes(
                session_id, compromised_refs, compromised=True, source=source
            )
        if high_value_refs:
            results["high_value"] = self.mark_nodes(
                session_id, high_value_refs, high_value=True, source=source
            )
        return results

    def list_markings(self, session_id: str) -> dict[str, Any]:
        if neo4j_configured():
            neo = neo4j_reads.list_markings(session_id)
            if neo is not None:
                return {"session_id": session_id, **neo}
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        summary = summarize_markings(session.snapshot)
        return {"session_id": session_id, **summary}

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
        if neo4j_configured():
            write_snapshot(record.snapshot, session_meta=self._neo4j_meta(record))

    def _load_from_neo4j(self, session_id: str) -> SessionRecord | None:
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
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {}
        return SessionRecord(
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


def is_demo_session(session_id: str, metadata: dict[str, Any] | None = None) -> bool:
    metadata = metadata or {}
    if metadata.get("fixture_id") or metadata.get("demo"):
        return True
    if metadata.get("sample"):
        return True
    return session_id.startswith("sample-") or session_id.startswith("fixture-")
