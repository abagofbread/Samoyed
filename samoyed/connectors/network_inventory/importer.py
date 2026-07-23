from __future__ import annotations

from typing import Any

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.connectors._shared import aws_scope, build_session_from_artifacts, parse_json_payload
from samoyed.graph.builder import GraphBuilder
from samoyed.network.enrich import enrich_network_reachability
from samoyed.network.model import NetworkInventory


def import_network_inventory(
    payload: bytes | str,
    *,
    session_id: str,
    caller_arn: str | None = None,
    session_store: Any | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    data = parse_json_payload(payload)
    if not isinstance(data, dict):
        raise ValueError("network-inventory must be a JSON object")

    inventory = NetworkInventory.from_dict(data)
    inventory.source = inventory.source or "network-inventory"
    if inventory.is_empty() and not data.get("resources"):
        raise ValueError("network-inventory has no placements/peerings/sg_rules")

    account_id = str(data.get("account_id") or _primary_account(inventory) or "unknown")
    scope_id, scope_display = aws_scope(account_id)
    artifacts: list[ConceptArtifact] = []

    for resource in data.get("resources") or []:
        native_id = resource.get("id") or resource.get("native_id")
        if not native_id:
            continue
        concept_name = resource.get("concept") or "RuntimeBinding"
        concept = {
            "Identity": ConceptType.IDENTITY,
            "RuntimeBinding": ConceptType.RUNTIME_BINDING,
            "DataStore": ConceptType.DATA_STORE,
            "SecretStore": ConceptType.SECRET_STORE,
        }.get(str(concept_name), ConceptType.RUNTIME_BINDING)
        props = {
            "resource_type": resource.get("type") or resource.get("resource_type"),
            "display_name": resource.get("display_name") or resource.get("name") or native_id,
            "source": "network-inventory",
            **{
                k: resource[k]
                for k in (
                    "vpc_id",
                    "sg_ids",
                    "subnet_ids",
                    "private_ips",
                    "public_ip",
                    "account_id",
                    "execution_role_arn",
                    "is_caller",
                )
                if resource.get(k) is not None
            },
        }
        artifacts.append(
            ConceptArtifact(
                concept_type=concept,
                provider=CloudProvider.AWS,
                native_id=str(native_id),
                scope_id=scope_id,
                properties=props,
                evidence=Evidence("network-inventory:resource", {"id": native_id}),
            )
        )

    for placement in inventory.placements:
        if any(a.native_id == placement.native_id for a in artifacts):
            continue
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.AWS,
                native_id=placement.native_id,
                scope_id=aws_scope(placement.account_id or account_id)[0],
                properties={
                    "resource_type": placement.resource_type or "EC2Instance",
                    "display_name": placement.native_id,
                    "vpc_id": placement.vpc_id,
                    "sg_ids": list(placement.sg_ids),
                    "subnet_ids": list(placement.subnet_ids),
                    "private_ips": list(placement.private_ips),
                    "public_ip": placement.public_ip,
                    "account_id": placement.account_id or account_id,
                    "source": "network-inventory",
                },
                evidence=Evidence("network-inventory:placement", {"id": placement.native_id}),
            )
        )

    if not artifacts:
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=CloudProvider.AWS,
                native_id=f"arn:aws:iam::{account_id}:root",
                scope_id=scope_id,
                properties={
                    "native_kind": "Root",
                    "display_name": f"account-root:{account_id}",
                    "is_caller": True,
                    "source": "network-inventory",
                },
                evidence=Evidence("network-inventory:root", {"account_id": account_id}),
            )
        )

    builder, meta = build_session_from_artifacts(
        artifacts,
        session_id=session_id,
        source="network-inventory",
        scope_id=scope_id,
        scope_display=scope_display,
        caller_arn=caller_arn,
        provider=CloudProvider.AWS,
        account_id=account_id,
        network=inventory,
        session_store=session_store,
    )
    meta["provider"] = CloudProvider.AWS.value
    return builder, meta


def attach_network_inventory_to_builder(
    builder: GraphBuilder,
    payload: bytes | str | dict[str, Any],
    *,
    session_store: Any | None = None,
) -> dict[str, Any]:
    if isinstance(payload, dict):
        data = payload
    else:
        data = parse_json_payload(payload)
    inventory = NetworkInventory.from_dict(data if isinstance(data, dict) else None)
    inventory.source = inventory.source or "network-inventory"
    stats = enrich_network_reachability(
        builder,
        inventory,
        session_store=session_store,
        inventory_source=inventory.source,
    )
    return {"network_enrichment": stats, "network_inventory": inventory.to_dict()}


def _primary_account(inventory: NetworkInventory) -> str | None:
    for p in inventory.placements:
        if p.account_id:
            return p.account_id
    for peering in inventory.peerings:
        if peering.local_account_id:
            return peering.local_account_id
    return None
