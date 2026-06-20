from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from samoyed.cloud.concepts import CloudProvider
from samoyed.credentials.protocol import ScopeBoundary


class AwsCredential:
    provider = CloudProvider.AWS

    def __init__(
        self,
        *,
        profile: str | None = None,
        region: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        session_token: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.endpoint_url = endpoint_url or os.environ.get("AWS_ENDPOINT_URL")
        session_kwargs: dict[str, Any] = {"region_name": self.region}
        if profile:
            session_kwargs["profile_name"] = profile
        if access_key and secret_key:
            session_kwargs["aws_access_key_id"] = access_key
            session_kwargs["aws_secret_access_key"] = secret_key
            if session_token:
                session_kwargs["aws_session_token"] = session_token
        self._session = boto3.Session(**session_kwargs)
        self._caller: dict[str, Any] | None = None

    @classmethod
    def from_key_file(cls, path: Path, region: str | None = None) -> AwsCredential:
        data = json.loads(path.read_text())
        return cls(
            access_key=data.get("AccessKeyId") or data.get("access_key_id"),
            secret_key=data.get("SecretAccessKey") or data.get("secret_access_key"),
            session_token=data.get("SessionToken") or data.get("session_token"),
            region=region or data.get("region"),
            endpoint_url=data.get("endpoint_url"),
        )

    @classmethod
    def from_env(cls, region: str | None = None, endpoint_url: str | None = None) -> AwsCredential:
        return cls(
            access_key=os.environ.get("AWS_ACCESS_KEY_ID"),
            secret_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            session_token=os.environ.get("AWS_SESSION_TOKEN"),
            region=region,
            endpoint_url=endpoint_url,
        )

    @classmethod
    def from_profile(
        cls,
        profile: str,
        *,
        region: str | None = None,
        endpoint_url: str | None = None,
    ) -> AwsCredential:
        return cls(profile=profile, region=region, endpoint_url=endpoint_url)

    def client(self, service: str, region: str | None = None) -> Any:
        kwargs: dict[str, Any] = {"region_name": region or self.region}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        return self._session.client(service, **kwargs)

    def get_caller_identity(self) -> dict[str, Any]:
        if self._caller is None:
            self._caller = self.client("sts").get_caller_identity()
        return self._caller

    def resolve_scope(self) -> ScopeBoundary:
        ident = self.get_caller_identity()
        account = ident["Account"]
        return ScopeBoundary(
            provider=CloudProvider.AWS,
            scope_id=f"aws:account:{account}",
            display_name=f"AWS Account {account}",
            properties={"account_id": account, "arn": ident["Arn"], "user_id": ident["UserId"]},
        )

    def fingerprint(self) -> str:
        ident = self.get_caller_identity()
        return ident["Arn"]


def is_access_denied(exc: Exception) -> bool:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
    return False
