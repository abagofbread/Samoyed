"""Collect GCP VPC / firewall / peering inventory into portable NetworkInventory."""

from __future__ import annotations

from typing import Any

from samoyed.credentials.protocol import EnumContext
from samoyed.cloud.artifacts import DenialRecord
from samoyed.cloud.concepts import CloudProvider
from samoyed.enumerators.gcp.helpers import is_gcp_denied
from samoyed.network.model import NetworkInventory, NetworkPlacement, PeeringLink, SgIngressRule


def collect_gcp_network_inventory(ctx: EnumContext) -> NetworkInventory:
    inventory = NetworkInventory(provider="gcp", source="gcp-enum")
    project = str(ctx.scope.properties.get("project_id") or "")
    if not project:
        return inventory

    cred = ctx.credentials
    try:
        from google.auth.transport.requests import AuthorizedSession
    except ImportError:
        return inventory

    try:
        session = AuthorizedSession(cred.credentials())  # type: ignore[attr-defined]
    except Exception:
        return inventory

    networks = _get_json(
        ctx,
        session,
        f"https://compute.googleapis.com/compute/v1/projects/{project}/global/networks",
        operation="compute.networks.list",
    )
    for net in networks.get("items") or []:
        name = str(net.get("name") or "")
        if not name:
            continue
        cidrs: list[str] = []
        if net.get("IPv4Range"):
            cidrs.append(str(net["IPv4Range"]))
        inventory.vpc_cidrs[name] = cidrs

    subnets = _get_json(
        ctx,
        session,
        f"https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/subnetworks",
        operation="compute.subnetworks.aggregatedList",
    )
    subnet_cidrs: dict[str, str] = {}
    for _zone, payload in (subnets.get("items") or {}).items():
        for subnet in payload.get("subnetworks") or []:
            name = str(subnet.get("name") or "")
            cidr = str(subnet.get("ipCidrRange") or "")
            network = str(subnet.get("network") or "").rstrip("/").split("/")[-1]
            if name and cidr:
                subnet_cidrs[name] = cidr
            if network and cidr:
                inventory.vpc_cidrs.setdefault(network, [])
                if cidr not in inventory.vpc_cidrs[network]:
                    inventory.vpc_cidrs[network].append(cidr)

    firewalls = _get_json(
        ctx,
        session,
        f"https://compute.googleapis.com/compute/v1/projects/{project}/global/firewalls",
        operation="compute.firewalls.list",
    )
    for fw in firewalls.get("items") or []:
        if str(fw.get("direction") or "INGRESS").upper() != "INGRESS":
            continue
        fw_id = str(fw.get("name") or fw.get("id") or "")
        if not fw_id:
            continue
        cidrs = [str(c) for c in (fw.get("sourceRanges") or [])]
        inventory.sg_rules.append(
            SgIngressRule(
                sg_id=fw_id,
                direction="ingress",
                cidrs=cidrs,
                protocol=_first_protocol(fw.get("allowed") or []),
            )
        )

    peerings_seen: set[str] = set()
    for net in networks.get("items") or []:
        local_vpc = str(net.get("name") or "")
        for peering in net.get("peerings") or []:
            peer_id = str(peering.get("name") or "")
            remote_link = str(peering.get("network") or "")
            remote_vpc = remote_link.rstrip("/").split("/")[-1]
            remote_project = ""
            if "/projects/" in remote_link:
                remote_project = remote_link.split("/projects/")[1].split("/")[0]
            key = f"{local_vpc}:{remote_vpc}:{peer_id}"
            if key in peerings_seen:
                continue
            peerings_seen.add(key)
            inventory.peerings.append(
                PeeringLink(
                    id=peer_id or key,
                    status=str(peering.get("state") or "ACTIVE"),
                    local_vpc_id=local_vpc,
                    local_account_id=project,
                    remote_vpc_id=remote_vpc,
                    remote_account_id=remote_project or project,
                    local_cidrs=list(inventory.vpc_cidrs.get(local_vpc) or []),
                    remote_cidrs=list(inventory.vpc_cidrs.get(remote_vpc) or []),
                )
            )

    instances = _get_json(
        ctx,
        session,
        f"https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances",
        operation="compute.instances.aggregatedList",
    )
    for _zone, payload in (instances.get("items") or {}).items():
        for inst in payload.get("instances") or []:
            name = str(inst.get("name") or "")
            if not name:
                continue
            network_ifaces = inst.get("networkInterfaces") or []
            vpc_id = ""
            subnet_ids: list[str] = []
            private_ips: list[str] = []
            public_ip = None
            for iface in network_ifaces:
                network = str(iface.get("network") or "").rstrip("/").split("/")[-1]
                subnet = str(iface.get("subnetwork") or "").rstrip("/").split("/")[-1]
                if network:
                    vpc_id = network
                if subnet:
                    subnet_ids.append(subnet)
                if iface.get("networkIP"):
                    private_ips.append(str(iface["networkIP"]))
                for access in iface.get("accessConfigs") or []:
                    if access.get("natIP"):
                        public_ip = str(access["natIP"])
            tags = [str(t) for t in ((inst.get("tags") or {}).get("items") or [])]
            inventory.placements.append(
                NetworkPlacement(
                    native_id=f"GCEInstance:{name}",
                    account_id=project,
                    vpc_id=vpc_id,
                    subnet_ids=subnet_ids,
                    private_ips=private_ips,
                    public_ip=public_ip,
                    sg_ids=tags,
                    exposed_internet=bool(public_ip),
                    resource_type="GCEInstance",
                )
            )

    return inventory


def _get_json(ctx: EnumContext, session: Any, url: str, *, operation: str) -> dict[str, Any]:
    try:
        resp = session.get(url, timeout=30)
        if resp.status_code in {401, 403}:
            ctx.denial_log.add(
                DenialRecord(
                    provider=CloudProvider.GCP,
                    operation=operation,
                    error_code=str(resp.status_code),
                    message=resp.text[:200],
                )
            )
            return {}
        if resp.status_code >= 400:
            return {}
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        if is_gcp_denied(exc):
            return {}
        return {}


def _first_protocol(allowed: list[dict[str, Any]]) -> str:
    if not allowed:
        return "-1"
    proto = str(allowed[0].get("IPProtocol") or "-1")
    return proto
