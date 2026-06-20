from __future__ import annotations

from unittest.mock import MagicMock, patch

from samoyed.firing_range.config import COMPOSE_FILE, LAB_ADMIN_ROLE, LAB_BUCKET, LAB_SECRET, LAB_USER
from samoyed.firing_range.seed import ping_emulator, seed_aws_lab


def test_compose_file_exists():
    assert COMPOSE_FILE.is_file()


@patch("samoyed.firing_range.seed._client")
def test_seed_aws_lab_creates_topology(mock_client_factory):
    iam = MagicMock()
    sts = MagicMock()
    s3 = MagicMock()
    secrets = MagicMock()

    def factory(service: str, **kwargs):
        return {"iam": iam, "sts": sts, "s3": s3, "secretsmanager": secrets}[service]

    mock_client_factory.side_effect = factory

    sts.get_caller_identity.return_value = {"Account": "000000000000"}
    iam.create_user.return_value = {}
    iam.create_role.return_value = {"Role": {"Arn": f"arn:aws:iam::000000000000:role/{LAB_ADMIN_ROLE}"}}
    iam.get_role.return_value = {"Role": {"Arn": f"arn:aws:iam::000000000000:role/{LAB_ADMIN_ROLE}"}}
    secrets.create_secret.return_value = {
        "ARN": f"arn:aws:secretsmanager:us-east-1:000000000000:secret:{LAB_SECRET}"
    }

    meta = seed_aws_lab(endpoint_url="http://localhost:4566", region="us-east-1")

    assert meta["account_id"] == "000000000000"
    assert meta["caller_arn"].endswith(f"user/{LAB_USER}")
    assert meta["bucket"] == LAB_BUCKET
    iam.create_user.assert_called_once_with(UserName=LAB_USER)
    iam.create_role.assert_called_once()
    s3.create_bucket.assert_called_once()
    secrets.create_secret.assert_called_once_with(Name=LAB_SECRET, SecretString="emulated-db-password")


@patch("samoyed.firing_range.seed._client")
def test_ping_emulator(mock_client_factory):
    sts = MagicMock()
    mock_client_factory.return_value = sts
    sts.get_caller_identity.return_value = {"Account": "1"}
    assert ping_emulator(endpoint_url="http://localhost:4566") is True

    sts.get_caller_identity.side_effect = RuntimeError("down")
    assert ping_emulator(endpoint_url="http://localhost:4566") is False
