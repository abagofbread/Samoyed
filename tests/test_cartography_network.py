from __future__ import annotations

from unittest.mock import MagicMock

from samoyed.connectors.cartography import queries as cq
from samoyed.connectors.cartography.importer import import_cartography_graph


def _mock_client(rows_by_query: dict[str, list[dict]]) -> MagicMock:
    client = MagicMock()

    def run(query: str, **params: object) -> list[dict]:
        for key, rows in rows_by_query.items():
            if key in query or " ".join(key.split()) == " ".join(query.split()):
                return rows
        return []

    client.run.side_effect = run
    client.ping.return_value = True
    return client


def test_cartography_network_enrichment():
    client = _mock_client(
        {
            cq.AWS_ACCOUNTS: [{"account_id": "111111111111", "name": "dev"}],
            cq.AWS_PRINCIPALS: [
                {
                    "arn": "arn:aws:iam::111111111111:role/dev",
                    "labels": ["AWSRole"],
                    "name": "dev",
                    "account_id": "111111111111",
                }
            ],
            cq.STS_ASSUME_ROLE_ALLOW: [],
            cq.LAMBDA_ASSUMES_ROLE: [],
            cq.EC2_INSTANCE_PROFILE_ROLE: [
                {
                    "instance_id": "i-dev1",
                    "instance_arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-dev1",
                    "role_arn": "arn:aws:iam::111111111111:role/dev",
                }
            ],
            cq.S3_ACCESS: [],
            cq.SECRETS_MANAGER: [],
            cq.DYNAMODB_ACCESS: [],
            cq.K8S_CLUSTER: [],
            cq.K8S_SA: [],
            cq.GCP_SERVICE_ACCOUNTS: [],
            cq.EC2_NETWORK_PLACEMENT: [
                {
                    "instance_id": "i-dev1",
                    "instance_arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-dev1",
                    "vpc_id": "vpc-dev",
                    "subnet_ids": ["subnet-1"],
                    "sg_ids": ["sg-web"],
                    "private_ip": "10.0.1.10",
                    "public_ip": "203.0.113.10",
                    "exposed_internet": True,
                }
            ],
            cq.AWS_VPC_CIDRS: [{"vpc_id": "vpc-dev", "cidrs": ["10.0.0.0/16"]}],
            cq.AWS_PEERING_CONNECTIONS: [
                {
                    "peering_id": "pcx-1",
                    "status": "active",
                    "local_vpc_id": "vpc-dev",
                    "remote_vpc_id": "vpc-prod",
                    "local_account_id": "111111111111",
                    "remote_account_id": "222222222222",
                    "local_cidrs": ["10.0.0.0/16"],
                    "remote_cidrs": ["10.1.0.0/16"],
                }
            ],
            cq.EC2_SG_INGRESS: [
                {
                    "sg_id": "sg-web",
                    "cidrs": ["0.0.0.0/0"],
                    "referenced_sg_ids": [],
                    "from_port": 443,
                    "to_port": 443,
                    "protocol": "tcp",
                }
            ],
        }
    )
    builder, meta = import_cartography_graph(client, session_id="carto-net", account_id="111111111111")
    assert meta.get("network_enrichment")
    assert any(e.rel_type == "VPC_PEERS" for e in builder.snapshot.edges)
    assert any(
        e.rel_type == "CAN_REACH"
        and builder.snapshot.nodes[e.src_id].props.get("native_id") == "network:internet"
        for e in builder.snapshot.edges
    )
