from __future__ import annotations

from unittest.mock import MagicMock

from samoyed.cloud.concepts import CloudProvider
from samoyed.credentials.protocol import EnumContext, ScopeBoundary
from samoyed.enumerators.aws.network import collect_aws_network_inventory
from samoyed.cloud.artifacts import DenialLog


def test_collect_aws_network_inventory_mocked():
    ec2 = MagicMock()
    ec2.describe_vpcs.return_value = {
        "Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}],
    }
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-1",
                "IpPermissions": [
                    {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}
                ],
            }
        ]
    }
    ec2.describe_vpc_peering_connections.return_value = {
        "VpcPeeringConnections": [
            {
                "VpcPeeringConnectionId": "pcx-1",
                "Status": {"Code": "active"},
                "RequesterVpcInfo": {
                    "VpcId": "vpc-1",
                    "OwnerId": "111111111111",
                    "CidrBlock": "10.0.0.0/16",
                },
                "AccepterVpcInfo": {
                    "VpcId": "vpc-2",
                    "OwnerId": "222222222222",
                    "CidrBlock": "10.1.0.0/16",
                },
            }
        ]
    }
    ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-abc",
                        "VpcId": "vpc-1",
                        "SubnetId": "subnet-1",
                        "PrivateIpAddress": "10.0.1.5",
                        "PublicIpAddress": "203.0.113.5",
                        "SecurityGroups": [{"GroupId": "sg-1"}],
                    }
                ]
            }
        ]
    }

    lam = MagicMock()
    lam.list_functions.return_value = {
        "Functions": [
            {
                "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:fn",
                "VpcConfig": {
                    "VpcId": "vpc-1",
                    "SubnetIds": ["subnet-1"],
                    "SecurityGroupIds": ["sg-1"],
                },
            }
        ]
    }

    cred = MagicMock()
    cred.client.side_effect = lambda name: ec2 if name == "ec2" else lam

    ctx = EnumContext(
        credentials=cred,
        session_id="s1",
        scope=ScopeBoundary(
            provider=CloudProvider.AWS,
            scope_id="aws:account:111111111111",
            display_name="acct",
            properties={"account_id": "111111111111"},
        ),
        denial_log=DenialLog(),
    )
    inv = collect_aws_network_inventory(ctx)
    assert inv.vpc_cidrs["vpc-1"] == ["10.0.0.0/16"]
    assert any(p.native_id == "EC2Instance:i-abc" for p in inv.placements)
    assert any(p.native_id.startswith("LambdaFunction:") for p in inv.placements)
    assert inv.peerings[0].remote_account_id == "222222222222"
    assert any(r.sg_id == "sg-1" and "0.0.0.0/0" in r.cidrs for r in inv.sg_rules)
