from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.connectors._shared import aws_scope, build_session_from_artifacts, parse_json_payload
from samoyed.graph.builder import GraphBuilder
from samoyed.network.model import NetworkInventory, NetworkPlacement

CONCEPT_MAP = {
    "Identity": ConceptType.IDENTITY,
    "DataStore": ConceptType.DATA_STORE,
    "SecretStore": ConceptType.SECRET_STORE,
    "RuntimeBinding": ConceptType.RUNTIME_BINDING,
    "Workload": ConceptType.WORKLOAD,
    "Entitlement": ConceptType.ENTITLEMENT,
    "Trust": ConceptType.TRUST,
    "ManagementEndpoint": ConceptType.MANAGEMENT_ENDPOINT,
    "OrchestrationScope": ConceptType.ORCHESTRATION_SCOPE,
    "ScopeBoundary": ConceptType.SCOPE_BOUNDARY,
    "RegistryStore": ConceptType.REGISTRY_STORE,
    "NetworkExposure": ConceptType.NETWORK_EXPOSURE,
}


def import_iam_report(
    payload: bytes | str,
    *,
    session_id: str,
    caller_arn: str | None = None,
    session_store: Any | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    data = parse_json_payload(payload)
    if not isinstance(data, dict):
        raise ValueError("IAM report must be a JSON object")

    provider_name = str(data.get("provider") or "aws").lower()
    provider = CloudProvider(provider_name)
    account_id = str(data.get("account_id") or data.get("account") or "unknown")
    if data.get("scope_id"):
        scope_id = str(data["scope_id"])
        scope_display = data.get("scope_display") or scope_id
    elif provider == CloudProvider.AWS:
        scope_id, scope_display = aws_scope(account_id)
    else:
        scope_id = data.get("scope_id") or f"{provider_name}:scope:{account_id}"
        scope_display = data.get("scope_display") or scope_id

    artifacts = list(_artifacts_from_report(data, scope_id=scope_id, account_id=account_id, provider=provider))
    resolved_caller = caller_arn or data.get("caller_arn")
    network = _network_from_report(data, account_id=account_id)
    builder, meta = build_session_from_artifacts(
        artifacts,
        session_id=session_id,
        source="iam-report",
        scope_id=scope_id,
        scope_display=scope_display,
        caller_arn=resolved_caller,
        provider=provider,
        account_id=account_id if provider == CloudProvider.AWS else None,
        network=network,
        session_store=session_store,
    )
    if data.get("scenario"):
        meta["scenario"] = data["scenario"]
    if data.get("metadata"):
        meta.update(data["metadata"])
    meta["report_source"] = data.get("source")
    meta["collected_via"] = data.get("collected_via")
    meta["provider"] = provider.value
    return builder, meta


def _artifacts_from_report(
    data: dict[str, Any],
    *,
    scope_id: str,
    account_id: str,
    provider: CloudProvider = CloudProvider.AWS,
) -> Iterator[ConceptArtifact]:
    for identity in data.get("identities") or []:
        arn = identity.get("arn") or identity.get("id")
        if not arn:
            continue
        props = {
            "native_kind": identity.get("kind") or _kind_from_arn(arn),
            "arn": identity.get("arn") or (arn if arn.startswith("arn:") else None),
            "name": identity.get("name"),
            "display_name": identity.get("display_name") or identity.get("name") or arn,
            "source": "iam-report",
        }
        if identity.get("is_caller"):
            props["is_caller"] = True
        if identity.get("is_scenario_start"):
            props["is_scenario_start"] = True
        for key in ("ou", "namespace", "provider", "notes", "assume_role_policy"):
            if identity.get(key) is not None:
                props[key] = identity[key]
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=provider,
            native_id=arn,
            scope_id=scope_id,
            properties=props,
            evidence=Evidence("iam-report:identity", {"arn": arn}),
            edges=_grants_for(data, from_id=arn),
        )

    for resource in data.get("resources") or []:
        native_id = resource.get("id") or resource.get("native_id")
        if not native_id:
            continue
        concept_name = resource.get("concept") or resource.get("concept_type") or "DataStore"
        concept = CONCEPT_MAP.get(concept_name, ConceptType.DATA_STORE)
        props = {
            "resource_type": resource.get("type") or resource.get("resource_type"),
            "name": resource.get("name"),
            "display_name": resource.get("display_name") or resource.get("name") or native_id,
            "source": "iam-report",
        }
        if resource.get("is_scenario_start"):
            props["is_scenario_start"] = True
        for key in (
            "bucket_name",
            "function_name",
            "namespace",
            "cluster",
            "ou",
            "severity",
            "instance_id",
            "secret_name",
            "vault_name",
            "account_name",
            "resource_group",
            "client_id",
            "service_account",
            "environment",
            "sensitivity",
            "scope_boundary",
            "ssrf_vulnerable",
            "has_public_url",
            "has_public_reach",
            "public_write",
            "public_read",
            "internet_write",
            "internal_only",
            "exposure_level",
            "execution_role_arn",
            "instance_type",
            "compute_class",
            "gpu_accelerated",
            "vpc_id",
            "sg_ids",
            "security_group_ids",
            "subnet_ids",
            "private_ips",
            "private_ip",
            "public_ip",
            "account_id",
            "exposed_internet",
        ):
            if resource.get(key) is not None:
                props[key] = resource[key]
        yield ConceptArtifact(
            concept_type=concept,
            provider=provider,
            native_id=native_id,
            scope_id=scope_id,
            properties=props,
            evidence=Evidence("iam-report:resource", {"id": native_id}),
            edges=_grants_for(data, from_id=native_id),
        )

    if not data.get("identities") and data.get("grants"):
        for grant in data["grants"]:
            src = grant.get("from")
            if not src:
                continue
            yield ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=provider,
                native_id=src,
                scope_id=scope_id,
                properties={
                    "native_kind": _kind_from_arn(src),
                    "arn": src if src.startswith("arn:") else None,
                    "display_name": src,
                    "source": "iam-report",
                },
                evidence=Evidence("iam-report:grant-src", {"from": src}),
                edges=[_grant_edge(grant)],
            )


def _grants_for(data: dict[str, Any], from_id: str) -> list[ConceptEdge]:
    edges: list[ConceptEdge] = []
    for grant in data.get("grants") or []:
        if grant.get("from") != from_id:
            continue
        edges.append(_grant_edge(grant))
    return edges


def _grant_edge(grant: dict[str, Any]) -> ConceptEdge:
    rel = grant.get("rel") or grant.get("relationship") or "READS"
    target = grant.get("to") or grant.get("target")
    props = {k: v for k, v in grant.items() if k not in {"from", "to", "rel", "relationship", "target"}}
    if grant.get("action"):
        props["action"] = grant["action"]
    props["source"] = "iam-report"
    return ConceptEdge(rel_type=rel, target_native_id=target or "", props=props)


def _kind_from_arn(arn: str) -> str:
    if ":role/" in arn:
        return "Role"
    if ":user/" in arn:
        return "User"
    return "Identity"


def _network_from_report(data: dict[str, Any], *, account_id: str) -> NetworkInventory:
    inventory = NetworkInventory.from_dict(data.get("network") if isinstance(data.get("network"), dict) else None)
    if inventory.source == "":
        inventory.source = "iam-report"
    for resource in data.get("resources") or []:
        native_id = resource.get("id") or resource.get("native_id")
        vpc_id = resource.get("vpc_id")
        sg_ids = resource.get("sg_ids") or resource.get("security_group_ids") or []
        if not native_id or (not vpc_id and not sg_ids):
            continue
        if isinstance(sg_ids, str):
            sg_ids = [sg_ids]
        private_ips = list(resource.get("private_ips") or [])
        if resource.get("private_ip") and resource["private_ip"] not in private_ips:
            private_ips.append(resource["private_ip"])
        inventory.placements.append(
            NetworkPlacement(
                native_id=str(native_id),
                account_id=str(resource.get("account_id") or account_id),
                vpc_id=str(vpc_id or ""),
                subnet_ids=[str(x) for x in (resource.get("subnet_ids") or [])],
                private_ips=[str(x) for x in private_ips],
                public_ip=resource.get("public_ip"),
                sg_ids=[str(x) for x in sg_ids],
                exposed_internet=bool(resource.get("exposed_internet")),
                resource_type=str(resource.get("type") or resource.get("resource_type") or ""),
            )
        )
    return inventory
