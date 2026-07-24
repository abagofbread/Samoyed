"""Collect Azure VNet / NSG / peering inventory into portable NetworkInventory."""

from __future__ import annotations

from typing import Any

from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.azure.helpers import call_azure
from samoyed.enumerators.azure.targets import resource_group_from_id
from samoyed.network.model import NetworkInventory, NetworkPlacement, PeeringLink, SgIngressRule


def collect_azure_network_inventory(ctx: EnumContext) -> NetworkInventory:
    inventory = NetworkInventory(provider="azure", source="azure-enum")
    subscription_id = str(ctx.scope.properties.get("subscription_id") or "")
    if not subscription_id:
        return inventory

    cred = ctx.credentials
    try:
        network = cred.client("network")  # type: ignore[attr-defined]
    except ImportError:
        return inventory

    _collect_vnets(ctx, network, inventory, subscription_id=subscription_id)
    _collect_nsgs(ctx, network, inventory)
    _collect_peerings(ctx, network, inventory, subscription_id=subscription_id)
    _collect_vm_placements(ctx, network, inventory, subscription_id=subscription_id)
    return inventory


def _collect_vnets(
    ctx: EnumContext, network: Any, inventory: NetworkInventory, *, subscription_id: str
) -> None:
    del subscription_id
    vnets = call_azure(
        ctx,
        operation="network.virtualNetworks.listAll",
        call=lambda: list(network.virtual_networks.list_all()),
    )
    if not vnets:
        return
    for vnet in vnets:
        name = getattr(vnet, "name", None) or ""
        if not name:
            continue
        cidrs: list[str] = []
        addr = getattr(vnet, "address_space", None)
        prefixes = getattr(addr, "address_prefixes", None) if addr else None
        if prefixes:
            cidrs.extend(str(p) for p in prefixes)
        for subnet in getattr(vnet, "subnets", None) or []:
            prefix = getattr(subnet, "address_prefix", None)
            if prefix:
                cidrs.append(str(prefix))
            for p in getattr(subnet, "address_prefixes", None) or []:
                cidrs.append(str(p))
        inventory.vpc_cidrs[name] = sorted(set(cidrs))


def _collect_nsgs(ctx: EnumContext, network: Any, inventory: NetworkInventory) -> None:
    nsgs = call_azure(
        ctx,
        operation="network.networkSecurityGroups.listAll",
        call=lambda: list(network.network_security_groups.list_all()),
    )
    if not nsgs:
        return
    for nsg in nsgs:
        nsg_id = getattr(nsg, "name", None) or getattr(nsg, "id", None)
        if not nsg_id:
            continue
        nsg_name = str(getattr(nsg, "name", None) or nsg_id)
        rules = list(getattr(nsg, "security_rules", None) or [])
        # default_security_rules often include AllowVnetInBound etc.; include custom + default
        rules.extend(list(getattr(nsg, "default_security_rules", None) or []))
        for rule in rules:
            direction = str(getattr(rule, "direction", "") or "").lower()
            access = str(getattr(rule, "access", "") or "").lower()
            if direction and direction != "inbound":
                continue
            if access and access != "allow":
                continue
            cidrs = _rule_cidrs(rule)
            inventory.sg_rules.append(
                SgIngressRule(
                    sg_id=nsg_name,
                    direction="ingress",
                    cidrs=cidrs,
                    protocol=str(getattr(rule, "protocol", None) or "-1"),
                    from_port=_port_or_none(getattr(rule, "destination_port_range", None)),
                    to_port=_port_or_none(getattr(rule, "destination_port_range", None)),
                )
            )


def _collect_peerings(
    ctx: EnumContext, network: Any, inventory: NetworkInventory, *, subscription_id: str
) -> None:
    vnets = call_azure(
        ctx,
        operation="network.virtualNetworks.listAll",
        call=lambda: list(network.virtual_networks.list_all()),
    )
    if not vnets:
        return
    seen: set[str] = set()
    for vnet in vnets:
        local_vpc = str(getattr(vnet, "name", None) or "")
        rg = resource_group_from_id(getattr(vnet, "id", None))
        if not local_vpc or not rg:
            continue
        peerings = call_azure(
            ctx,
            operation=f"network.virtualNetworkPeerings.list:{local_vpc}",
            call=lambda rg=rg, name=local_vpc: list(
                network.virtual_network_peerings.list(rg, name)
            ),
        )
        if not peerings:
            continue
        for peering in peerings:
            peer_id = str(getattr(peering, "name", None) or "")
            remote_id = str(getattr(peering, "remote_virtual_network", None) or "")
            # remote_virtual_network may be an object with .id
            if not remote_id or remote_id.startswith("<"):
                remote_obj = getattr(peering, "remote_virtual_network", None)
                remote_id = str(getattr(remote_obj, "id", None) or "")
            remote_vpc = remote_id.rstrip("/").split("/")[-1] if remote_id else ""
            remote_sub = ""
            if "/subscriptions/" in remote_id:
                remote_sub = remote_id.split("/subscriptions/")[1].split("/")[0]
            key = f"{local_vpc}:{remote_vpc}:{peer_id}"
            if key in seen:
                continue
            seen.add(key)
            status = str(
                getattr(peering, "peering_state", None)
                or getattr(peering, "provisioning_state", None)
                or "Connected"
            )
            inventory.peerings.append(
                PeeringLink(
                    id=peer_id or key,
                    status=status,
                    local_vpc_id=local_vpc,
                    local_account_id=subscription_id,
                    remote_vpc_id=remote_vpc,
                    remote_account_id=remote_sub or subscription_id,
                    local_cidrs=list(inventory.vpc_cidrs.get(local_vpc) or []),
                    remote_cidrs=list(inventory.vpc_cidrs.get(remote_vpc) or []),
                )
            )


def _collect_vm_placements(
    ctx: EnumContext, network: Any, inventory: NetworkInventory, *, subscription_id: str
) -> None:
    del network
    cred = ctx.credentials
    try:
        compute = cred.client("compute")  # type: ignore[attr-defined]
    except ImportError:
        return

    try:
        net_client = cred.client("network")  # type: ignore[attr-defined]
    except ImportError:
        net_client = None

    vms = call_azure(
        ctx,
        operation="compute.virtualMachines.listAll",
        call=lambda: list(compute.virtual_machines.list_all()),
    )
    if not vms:
        return

    for vm in vms:
        name = getattr(vm, "name", None)
        if not name:
            continue
        rg = resource_group_from_id(getattr(vm, "id", None))
        vpc_id = ""
        subnet_ids: list[str] = []
        private_ips: list[str] = []
        public_ip: str | None = None
        nsg_ids: list[str] = []

        # Prefer instance view / network profile NICs
        nic_refs = []
        profile = getattr(vm, "network_profile", None)
        if profile:
            nic_refs = list(getattr(profile, "network_interfaces", None) or [])

        for nic_ref in nic_refs:
            nic_id = str(getattr(nic_ref, "id", None) or nic_ref or "")
            if not nic_id or not net_client or not rg:
                continue
            nic_name = nic_id.rstrip("/").split("/")[-1]
            nic_rg = resource_group_from_id(nic_id) or rg
            nic = call_azure(
                ctx,
                operation=f"network.networkInterfaces.get:{nic_name}",
                call=lambda nic_rg=nic_rg, nic_name=nic_name: net_client.network_interfaces.get(
                    nic_rg, nic_name
                ),
            )
            if not nic:
                continue
            for ipconf in getattr(nic, "ip_configurations", None) or []:
                subnet = getattr(ipconf, "subnet", None)
                subnet_id = str(getattr(subnet, "id", None) or "")
                if subnet_id:
                    parts = subnet_id.split("/")
                    try:
                        vnet_idx = parts.index("virtualNetworks")
                        vpc_id = parts[vnet_idx + 1]
                    except (ValueError, IndexError):
                        pass
                    subnet_ids.append(subnet_id.rstrip("/").split("/")[-1])
                priv = getattr(ipconf, "private_ip_address", None)
                if priv:
                    private_ips.append(str(priv))
                pip_ref = getattr(ipconf, "public_ip_address", None)
                pip_id = str(getattr(pip_ref, "id", None) or "") if pip_ref else ""
                if pip_id and net_client:
                    pip_name = pip_id.rstrip("/").split("/")[-1]
                    pip_rg = resource_group_from_id(pip_id) or nic_rg
                    pip = call_azure(
                        ctx,
                        operation=f"network.publicIPAddresses.get:{pip_name}",
                        call=lambda pip_rg=pip_rg, pip_name=pip_name: net_client.public_ip_addresses.get(
                            pip_rg, pip_name
                        ),
                    )
                    if pip and getattr(pip, "ip_address", None):
                        public_ip = str(pip.ip_address)
            nsg = getattr(nic, "network_security_group", None)
            nsg_id = str(getattr(nsg, "id", None) or "") if nsg else ""
            if nsg_id:
                nsg_ids.append(nsg_id.rstrip("/").split("/")[-1])

        inventory.placements.append(
            NetworkPlacement(
                native_id=f"AzureVM:{name}",
                account_id=subscription_id,
                vpc_id=vpc_id,
                subnet_ids=subnet_ids,
                private_ips=private_ips,
                public_ip=public_ip,
                sg_ids=nsg_ids,
                exposed_internet=bool(public_ip),
                resource_type="AzureVM",
            )
        )


def _rule_cidrs(rule: Any) -> list[str]:
    cidrs: list[str] = []
    prefix = getattr(rule, "source_address_prefix", None)
    if prefix:
        cidrs.append(str(prefix) if str(prefix) != "*" else "0.0.0.0/0")
    for p in getattr(rule, "source_address_prefixes", None) or []:
        cidrs.append(str(p) if str(p) != "*" else "0.0.0.0/0")
    return cidrs


def _port_or_none(value: Any) -> int | None:
    if value is None or value == "*" or value == "":
        return None
    try:
        text = str(value)
        if "-" in text:
            return int(text.split("-", 1)[0])
        return int(text)
    except (TypeError, ValueError):
        return None
