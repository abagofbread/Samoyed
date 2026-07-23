from __future__ import annotations

from typing import Any

from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.runner import paginate_call
from samoyed.network.model import NetworkInventory, NetworkPlacement, PeeringLink, SgIngressRule


def collect_aws_network_inventory(ctx: EnumContext) -> NetworkInventory:
    """Collect VPC peering, SG ingress, and compute placement from live AWS APIs."""
    inventory = NetworkInventory(provider="aws", source="aws-enum")
    account_id = str(
        getattr(ctx.scope, "properties", {}).get("account_id")
        or _account_from_scope(ctx.scope.scope_id)
        or ""
    )
    cred = ctx.credentials
    try:
        ec2 = cred.client("ec2")  # type: ignore[attr-defined]
    except Exception:
        return inventory

    _collect_vpcs(ctx, ec2, inventory)
    _collect_security_groups(ctx, ec2, inventory)
    _collect_peerings(ctx, ec2, inventory, account_id=account_id)
    _collect_instance_placements(ctx, ec2, inventory, account_id=account_id)
    _collect_lambda_placements(ctx, inventory, account_id=account_id)
    return inventory


def _account_from_scope(scope_id: str) -> str | None:
    parts = scope_id.split(":")
    if len(parts) >= 3 and parts[0] == "aws":
        return parts[-1]
    return None


def _collect_vpcs(ctx: EnumContext, ec2: Any, inventory: NetworkInventory) -> None:
    resp = paginate_call(ctx, operation="ec2:DescribeVpcs", call=lambda: ec2.describe_vpcs())
    if not resp:
        return
    for vpc in resp.get("Vpcs", []):
        vpc_id = vpc.get("VpcId")
        if not vpc_id:
            continue
        cidrs = []
        if vpc.get("CidrBlock"):
            cidrs.append(str(vpc["CidrBlock"]))
        for assoc in vpc.get("CidrBlockAssociationSet") or []:
            if assoc.get("CidrBlock"):
                cidrs.append(str(assoc["CidrBlock"]))
        inventory.vpc_cidrs[str(vpc_id)] = sorted(set(cidrs))


def _collect_security_groups(ctx: EnumContext, ec2: Any, inventory: NetworkInventory) -> None:
    resp = paginate_call(
        ctx, operation="ec2:DescribeSecurityGroups", call=lambda: ec2.describe_security_groups()
    )
    if not resp:
        return
    for sg in resp.get("SecurityGroups", []):
        sg_id = sg.get("GroupId")
        if not sg_id:
            continue
        for perm in sg.get("IpPermissions") or []:
            cidrs = [str(r.get("CidrIp")) for r in (perm.get("IpRanges") or []) if r.get("CidrIp")]
            cidrs.extend(
                str(r.get("CidrIpv6")) for r in (perm.get("Ipv6Ranges") or []) if r.get("CidrIpv6")
            )
            refs = [
                str(r.get("GroupId"))
                for r in (perm.get("UserIdGroupPairs") or [])
                if r.get("GroupId")
            ]
            inventory.sg_rules.append(
                SgIngressRule(
                    sg_id=str(sg_id),
                    direction="ingress",
                    cidrs=cidrs,
                    referenced_sg_ids=refs,
                    from_port=perm.get("FromPort"),
                    to_port=perm.get("ToPort"),
                    protocol=str(perm.get("IpProtocol") or "-1"),
                )
            )


def _collect_peerings(
    ctx: EnumContext, ec2: Any, inventory: NetworkInventory, *, account_id: str
) -> None:
    resp = paginate_call(
        ctx,
        operation="ec2:DescribeVpcPeeringConnections",
        call=lambda: ec2.describe_vpc_peering_connections(),
    )
    if not resp:
        return
    for pcx in resp.get("VpcPeeringConnections", []):
        status = ((pcx.get("Status") or {}).get("Code")) or "active"
        requester = pcx.get("RequesterVpcInfo") or {}
        accepter = pcx.get("AccepterVpcInfo") or {}
        inventory.peerings.append(
            PeeringLink(
                id=str(pcx.get("VpcPeeringConnectionId") or ""),
                status=str(status),
                local_vpc_id=str(requester.get("VpcId") or ""),
                local_account_id=str(requester.get("OwnerId") or account_id),
                remote_vpc_id=str(accepter.get("VpcId") or ""),
                remote_account_id=str(accepter.get("OwnerId") or ""),
                local_cidrs=[str(c.get("CidrBlock")) for c in (requester.get("CidrBlockSet") or []) if c.get("CidrBlock")]
                or ([str(requester["CidrBlock"])] if requester.get("CidrBlock") else []),
                remote_cidrs=[str(c.get("CidrBlock")) for c in (accepter.get("CidrBlockSet") or []) if c.get("CidrBlock")]
                or ([str(accepter["CidrBlock"])] if accepter.get("CidrBlock") else []),
            )
        )


def _collect_instance_placements(
    ctx: EnumContext, ec2: Any, inventory: NetworkInventory, *, account_id: str
) -> None:
    resp = paginate_call(ctx, operation="ec2:DescribeInstances", call=lambda: ec2.describe_instances())
    if not resp:
        return
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            iid = inst.get("InstanceId")
            if not iid:
                continue
            sgs = [str(g.get("GroupId")) for g in (inst.get("SecurityGroups") or []) if g.get("GroupId")]
            inventory.placements.append(
                NetworkPlacement(
                    native_id=f"EC2Instance:{iid}",
                    account_id=account_id,
                    vpc_id=str(inst.get("VpcId") or ""),
                    subnet_ids=[str(inst["SubnetId"])] if inst.get("SubnetId") else [],
                    private_ips=[str(inst["PrivateIpAddress"])] if inst.get("PrivateIpAddress") else [],
                    public_ip=str(inst["PublicIpAddress"]) if inst.get("PublicIpAddress") else None,
                    sg_ids=sgs,
                    resource_type="EC2Instance",
                )
            )


def _collect_lambda_placements(
    ctx: EnumContext, inventory: NetworkInventory, *, account_id: str
) -> None:
    cred = ctx.credentials
    try:
        lam = cred.client("lambda")  # type: ignore[attr-defined]
    except Exception:
        return
    resp = paginate_call(ctx, operation="lambda:ListFunctions", call=lambda: lam.list_functions())
    if not resp:
        return
    for fn in resp.get("Functions", []):
        fn_arn = fn.get("FunctionArn")
        if not fn_arn:
            continue
        vpc = fn.get("VpcConfig") or {}
        subnet_ids = [str(x) for x in (vpc.get("SubnetIds") or [])]
        sg_ids = [str(x) for x in (vpc.get("SecurityGroupIds") or [])]
        vpc_id = str(vpc.get("VpcId") or "")
        if not (vpc_id or subnet_ids or sg_ids):
            continue
        inventory.placements.append(
            NetworkPlacement(
                native_id=f"LambdaFunction:{fn_arn}",
                account_id=account_id,
                vpc_id=vpc_id,
                subnet_ids=subnet_ids,
                sg_ids=sg_ids,
                resource_type="LambdaFunction",
            )
        )
