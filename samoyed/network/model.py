from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


INTERNET_NATIVE_ID = "network:internet"
NETWORK_ENRICHMENT_SOURCE = "network-enrichment"


@dataclass
class NetworkPlacement:
    native_id: str
    account_id: str = ""
    vpc_id: str = ""
    subnet_ids: list[str] = field(default_factory=list)
    private_ips: list[str] = field(default_factory=list)
    public_ip: str | None = None
    sg_ids: list[str] = field(default_factory=list)
    exposed_internet: bool = False
    resource_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "native_id": self.native_id,
            "account_id": self.account_id,
            "vpc_id": self.vpc_id,
            "subnet_ids": list(self.subnet_ids),
            "private_ips": list(self.private_ips),
            "public_ip": self.public_ip,
            "sg_ids": list(self.sg_ids),
            "exposed_internet": self.exposed_internet,
            "resource_type": self.resource_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetworkPlacement:
        return cls(
            native_id=str(data.get("native_id") or ""),
            account_id=str(data.get("account_id") or ""),
            vpc_id=str(data.get("vpc_id") or ""),
            subnet_ids=[str(x) for x in (data.get("subnet_ids") or [])],
            private_ips=[str(x) for x in (data.get("private_ips") or [])],
            public_ip=data.get("public_ip") or None,
            sg_ids=[str(x) for x in (data.get("sg_ids") or [])],
            exposed_internet=bool(data.get("exposed_internet")),
            resource_type=str(data.get("resource_type") or ""),
        )


@dataclass
class PeeringLink:
    id: str
    status: str = "active"
    local_vpc_id: str = ""
    local_account_id: str = ""
    remote_vpc_id: str = ""
    remote_account_id: str = ""
    local_cidrs: list[str] = field(default_factory=list)
    remote_cidrs: list[str] = field(default_factory=list)

    @property
    def is_active(self) -> bool:
        return str(self.status).lower() in {"active", "available", "ok", ""}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "local_vpc_id": self.local_vpc_id,
            "local_account_id": self.local_account_id,
            "remote_vpc_id": self.remote_vpc_id,
            "remote_account_id": self.remote_account_id,
            "local_cidrs": list(self.local_cidrs),
            "remote_cidrs": list(self.remote_cidrs),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PeeringLink:
        return cls(
            id=str(data.get("id") or ""),
            status=str(data.get("status") or "active"),
            local_vpc_id=str(data.get("local_vpc_id") or ""),
            local_account_id=str(data.get("local_account_id") or ""),
            remote_vpc_id=str(data.get("remote_vpc_id") or ""),
            remote_account_id=str(data.get("remote_account_id") or ""),
            local_cidrs=[str(x) for x in (data.get("local_cidrs") or [])],
            remote_cidrs=[str(x) for x in (data.get("remote_cidrs") or [])],
        )


@dataclass
class SgIngressRule:
    sg_id: str
    direction: str = "ingress"
    cidrs: list[str] = field(default_factory=list)
    referenced_sg_ids: list[str] = field(default_factory=list)
    from_port: int | None = None
    to_port: int | None = None
    protocol: str = "-1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sg_id": self.sg_id,
            "direction": self.direction,
            "cidrs": list(self.cidrs),
            "referenced_sg_ids": list(self.referenced_sg_ids),
            "from_port": self.from_port,
            "to_port": self.to_port,
            "protocol": self.protocol,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SgIngressRule:
        return cls(
            sg_id=str(data.get("sg_id") or ""),
            direction=str(data.get("direction") or "ingress"),
            cidrs=[str(x) for x in (data.get("cidrs") or [])],
            referenced_sg_ids=[str(x) for x in (data.get("referenced_sg_ids") or [])],
            from_port=data.get("from_port"),
            to_port=data.get("to_port"),
            protocol=str(data.get("protocol") or "-1"),
        )


@dataclass
class NetworkInventory:
    version: int = 1
    provider: str = "aws"
    placements: list[NetworkPlacement] = field(default_factory=list)
    peerings: list[PeeringLink] = field(default_factory=list)
    sg_rules: list[SgIngressRule] = field(default_factory=list)
    vpc_cidrs: dict[str, list[str]] = field(default_factory=dict)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "provider": self.provider,
            "placements": [p.to_dict() for p in self.placements],
            "peerings": [p.to_dict() for p in self.peerings],
            "sg_rules": [r.to_dict() for r in self.sg_rules],
            "vpc_cidrs": {k: list(v) for k, v in self.vpc_cidrs.items()},
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> NetworkInventory:
        if not data or not isinstance(data, dict):
            return cls()
        return cls(
            version=int(data.get("version") or 1),
            provider=str(data.get("provider") or "aws"),
            placements=[
                NetworkPlacement.from_dict(p)
                for p in (data.get("placements") or [])
                if isinstance(p, dict) and p.get("native_id")
            ],
            peerings=[
                PeeringLink.from_dict(p)
                for p in (data.get("peerings") or [])
                if isinstance(p, dict) and p.get("id")
            ],
            sg_rules=[
                SgIngressRule.from_dict(r)
                for r in (data.get("sg_rules") or [])
                if isinstance(r, dict) and r.get("sg_id")
            ],
            vpc_cidrs={
                str(k): [str(c) for c in (v or [])]
                for k, v in (data.get("vpc_cidrs") or {}).items()
            },
            source=str(data.get("source") or ""),
        )

    def merge(self, other: NetworkInventory | None) -> NetworkInventory:
        if other is None:
            return self
        by_native: dict[str, NetworkPlacement] = {p.native_id: p for p in self.placements}
        for p in other.placements:
            existing = by_native.get(p.native_id)
            if existing is None:
                by_native[p.native_id] = p
            else:
                by_native[p.native_id] = _merge_placement(existing, p)
        peering_ids = {p.id: p for p in self.peerings}
        for p in other.peerings:
            peering_ids[p.id] = p
        sg_keys: dict[tuple[str, tuple[str, ...], tuple[str, ...]], SgIngressRule] = {}
        for r in list(self.sg_rules) + list(other.sg_rules):
            key = (r.sg_id, tuple(sorted(r.cidrs)), tuple(sorted(r.referenced_sg_ids)))
            sg_keys[key] = r
        vpc_cidrs = dict(self.vpc_cidrs)
        for vpc_id, cidrs in other.vpc_cidrs.items():
            prev = set(vpc_cidrs.get(vpc_id, []))
            prev.update(cidrs)
            vpc_cidrs[vpc_id] = sorted(prev)
        return NetworkInventory(
            version=max(self.version, other.version),
            provider=self.provider or other.provider,
            placements=list(by_native.values()),
            peerings=list(peering_ids.values()),
            sg_rules=list(sg_keys.values()),
            vpc_cidrs=vpc_cidrs,
            source=self.source or other.source,
        )

    def is_empty(self) -> bool:
        return not (self.placements or self.peerings or self.sg_rules or self.vpc_cidrs)

    def placements_by_vpc(self, vpc_id: str) -> list[NetworkPlacement]:
        return [p for p in self.placements if p.vpc_id == vpc_id]

    def ingress_rules_for(self, sg_ids: Iterable[str]) -> list[SgIngressRule]:
        wanted = set(sg_ids)
        return [
            r
            for r in self.sg_rules
            if r.sg_id in wanted and str(r.direction).lower() in {"ingress", "in", ""}
        ]


def _merge_placement(a: NetworkPlacement, b: NetworkPlacement) -> NetworkPlacement:
    return NetworkPlacement(
        native_id=a.native_id,
        account_id=a.account_id or b.account_id,
        vpc_id=a.vpc_id or b.vpc_id,
        subnet_ids=sorted(set(a.subnet_ids) | set(b.subnet_ids)),
        private_ips=sorted(set(a.private_ips) | set(b.private_ips)),
        public_ip=a.public_ip or b.public_ip,
        sg_ids=sorted(set(a.sg_ids) | set(b.sg_ids)),
        exposed_internet=a.exposed_internet or b.exposed_internet,
        resource_type=a.resource_type or b.resource_type,
    )


def inventory_from_node_props(nodes: Iterable[Any]) -> NetworkInventory:
    """Derive a partial inventory from graph node placement props."""
    placements: list[NetworkPlacement] = []
    for node in nodes:
        props = getattr(node, "props", None) or {}
        native_id = props.get("native_id")
        vpc_id = props.get("vpc_id")
        sg_ids = props.get("sg_ids") or props.get("security_group_ids") or []
        if not native_id or (not vpc_id and not sg_ids):
            continue
        if isinstance(sg_ids, str):
            sg_ids = [sg_ids]
        private_ips = props.get("private_ips") or []
        if props.get("private_ip") and props["private_ip"] not in private_ips:
            private_ips = [*private_ips, props["private_ip"]]
        placements.append(
            NetworkPlacement(
                native_id=str(native_id),
                account_id=str(props.get("account_id") or ""),
                vpc_id=str(vpc_id or ""),
                subnet_ids=[str(x) for x in (props.get("subnet_ids") or [])],
                private_ips=[str(x) for x in private_ips],
                public_ip=props.get("public_ip"),
                sg_ids=[str(x) for x in sg_ids],
                exposed_internet=bool(props.get("exposed_internet")),
                resource_type=str(props.get("resource_type") or ""),
            )
        )
    return NetworkInventory(placements=placements, source="node-props")
