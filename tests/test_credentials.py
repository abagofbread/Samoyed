from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from samoyed.credentials.aws import AwsCredential, is_access_denied
from samoyed.credentials.loader import load_aws_credential
from samoyed.graph.neighbors import get_neighbors
from samoyed.graph.sample import build_sample_graph
from samoyed.path_engine.explain import explain_path
from samoyed.path_engine.search import find_attack_paths


def test_from_key_file(tmp_path: Path):
    key_path = tmp_path / "keys.json"
    key_path.write_text(
        '{"AccessKeyId":"AKIA","SecretAccessKey":"secret","region":"eu-west-1"}',
        encoding="utf-8",
    )
    cred = AwsCredential.from_key_file(key_path)
    assert cred.region == "eu-west-1"


@patch("samoyed.credentials.aws.boto3.Session")
def test_resolve_scope(mock_session_cls):
    sts = MagicMock()
    sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/test",
        "UserId": "AIDATEST",
    }
    session = MagicMock()
    session.client.return_value = sts
    mock_session_cls.return_value = session

    scope = AwsCredential(access_key="a", secret_key="b").resolve_scope()
    assert scope.scope_id == "aws:account:123456789012"
    assert scope.properties["arn"] == "arn:aws:iam::123456789012:user/test"


def test_load_aws_credential_prefers_key_file(tmp_path: Path):
    key_path = tmp_path / "keys.json"
    key_path.write_text('{"AccessKeyId":"AKIA","SecretAccessKey":"secret"}', encoding="utf-8")
    cred = load_aws_credential(key_file=key_path, profile="ignored")
    assert isinstance(cred, AwsCredential)


def test_is_access_denied():
    from botocore.exceptions import ClientError

    exc = ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetObject")
    assert is_access_denied(exc) is True


def test_get_neighbors_on_sample_graph():
    snapshot = build_sample_graph("neighbor-test")
    caller = next(n for n in snapshot.nodes.values() if n.props.get("is_caller"))
    neighbors = get_neighbors(snapshot, caller.node_id)
    assert len(neighbors) >= 1
    assert neighbors[0]["rel_type"] == "CAN_ASSUME_ROLE"


def test_explain_path_on_sample_scenario():
    snapshot = build_sample_graph("explain-test")
    caller = next(n for n in snapshot.nodes.values() if n.props.get("is_caller"))
    secret_paths = find_attack_paths(
        snapshot, start_node_id=caller.node_id, target_concept="SecretStore", max_depth=4
    )
    explanation = explain_path(snapshot, secret_paths[0])
    assert "summary" in explanation
    assert len(explanation["steps"]) >= 1
    assert "CAN_ASSUME_ROLE" in explanation["summary"] or any(
        s["relationship"] == "CAN_ASSUME_ROLE" for s in explanation["steps"]
    )
