from __future__ import annotations

from unittest.mock import MagicMock, patch

from samoyed.connectors.cartography import queries as cq
from samoyed.connectors.cartography.importer import import_cartography_graph
from samoyed.path_engine.search import find_attack_paths


def _mock_client(rows_by_query: dict[str, list[dict]]) -> MagicMock:
    client = MagicMock()

    def run(query: str, **params: object) -> list[dict]:
        normalized = " ".join(query.split())
        for key, rows in rows_by_query.items():
            if " ".join(key.split()) == normalized:
                return rows
        for key, rows in rows_by_query.items():
            if key in query:
                return rows
        return []

    client.run.side_effect = run
    client.ping.return_value = True
    return client


def _empty_k8s_gcp() -> dict[str, list[dict]]:
    return {
        cq.K8S_CLUSTER: [],
        cq.K8S_SA: [],
        cq.GCP_SERVICE_ACCOUNTS: [],
        cq.EC2_INSTANCE_PROFILE_ROLE: [],
        cq.DYNAMODB_ACCESS: [],
    }


def test_import_cartography_maps_assume_role_and_s3():
    client = _mock_client(
        {
            cq.AWS_ACCOUNTS: [{"account_id": "111111111111", "name": "prod"}],
            cq.AWS_PRINCIPALS: [
                {
                    "arn": "arn:aws:iam::111111111111:user/alice",
                    "labels": ["AWSPrincipal", "AWSUser"],
                    "name": "alice",
                    "account_id": "111111111111",
                },
                {
                    "arn": "arn:aws:iam::111111111111:role/admin",
                    "labels": ["AWSPrincipal", "AWSRole"],
                    "name": "admin",
                    "account_id": "111111111111",
                },
            ],
            cq.STS_ASSUME_ROLE_ALLOW: [
                {
                    "src_arn": "arn:aws:iam::111111111111:user/alice",
                    "dst_arn": "arn:aws:iam::111111111111:role/admin",
                }
            ],
            cq.S3_ACCESS: [
                {
                    "src_arn": "arn:aws:iam::111111111111:role/admin",
                    "access": "CAN_READ",
                    "bucket_native_id": "arn:aws:s3:::prod-data",
                    "bucket_name": "prod-data",
                }
            ],
            cq.SECRETS_MANAGER: [
                {
                    "arn": "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db",
                    "name": "prod-db",
                    "account_id": "111111111111",
                }
            ],
            cq.LAMBDA_ASSUMES_ROLE: [],
            **_empty_k8s_gcp(),
        }
    )

    builder, meta = import_cartography_graph(
        client,
        session_id="carto-test",
        caller_arn="arn:aws:iam::111111111111:user/alice",
        account_id="111111111111",
    )

    assert meta["source"] == "cartography"
    assert meta["node_count"] > 0
    rels = {e.rel_type for e in builder.snapshot.edges}
    assert "CAN_ASSUME_ROLE" in rels
    assert "READS" in rels

    caller = next(
        n for n in builder.snapshot.nodes.values() if n.props.get("arn", "").endswith("user/alice")
    )
    bucket_paths = find_attack_paths(
        builder.snapshot,
        start_node_id=caller.node_id,
        target_concept="DataStore",
        max_depth=5,
    )
    assert len(bucket_paths) >= 1


def test_import_cartography_lambda_executes_as():
    client = _mock_client(
        {
            cq.AWS_ACCOUNTS: [{"account_id": "111111111111", "name": "prod"}],
            cq.AWS_PRINCIPALS: [
                {
                    "arn": "arn:aws:iam::111111111111:role/lambda-admin",
                    "labels": ["AWSPrincipal", "AWSRole"],
                    "name": "lambda-admin",
                    "account_id": "111111111111",
                }
            ],
            cq.STS_ASSUME_ROLE_ALLOW: [],
            cq.LAMBDA_ASSUMES_ROLE: [
                {
                    "lambda_arn": "arn:aws:lambda:us-east-1:111111111111:function:tool",
                    "name": "tool",
                    "role_arn": "arn:aws:iam::111111111111:role/lambda-admin",
                }
            ],
            cq.S3_ACCESS: [],
            cq.SECRETS_MANAGER: [],
            **_empty_k8s_gcp(),
        }
    )

    builder, _meta = import_cartography_graph(client, session_id="carto-lambda", account_id="111111111111")
    assert any(e.rel_type == "EXECUTES_AS" for e in builder.snapshot.edges)


@patch("samoyed.connectors.cartography.client.CartographyClient")
def test_create_cartography_session(mock_client_cls):
    from samoyed.sessions import SessionStore

    mock_client = _mock_client(
        {
            cq.AWS_ACCOUNTS: [{"account_id": "111111111111", "name": "prod"}],
            cq.AWS_PRINCIPALS: [
                {
                    "arn": "arn:aws:iam::111111111111:user/alice",
                    "labels": ["AWSPrincipal", "AWSUser"],
                    "name": "alice",
                    "account_id": "111111111111",
                }
            ],
            cq.STS_ASSUME_ROLE_ALLOW: [],
            cq.S3_ACCESS: [],
            cq.SECRETS_MANAGER: [],
            cq.LAMBDA_ASSUMES_ROLE: [],
            **_empty_k8s_gcp(),
        }
    )
    mock_client_cls.return_value.__enter__.return_value = mock_client

    store = SessionStore()
    record = store.create_cartography_session(
        caller_arn="arn:aws:iam::111111111111:user/alice",
        account_id="111111111111",
        neo4j_uri="bolt://localhost:7687",
    )
    assert record.metadata.get("source") == "cartography"
    assert record.caller_arn.endswith("user/alice")
