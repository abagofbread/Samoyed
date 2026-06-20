from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from samoyed.cloud.concepts import CloudProvider
from samoyed.cloud.providers import make_scope_id
from samoyed.credentials.protocol import ScopeBoundary


def _require_google():
    try:
        import google.auth
        from google.oauth2 import service_account
    except ImportError as exc:
        raise ImportError("Install GCP support: pip install 'samoyed[gcp]'") from exc
    return google.auth, service_account


class GcpCredential:
    provider = CloudProvider.GCP

    def __init__(
        self,
        *,
        key_file: Path | str | None = None,
        project_id: str | None = None,
    ) -> None:
        google_auth, service_account = _require_google()
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")

        if key_file:
            path = str(key_file)
            self._credentials = service_account.Credentials.from_service_account_file(
                path,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            if not self.project_id:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
                self.project_id = data.get("project_id")
        else:
            self._credentials, default_project = google_auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            if not self.project_id:
                self.project_id = default_project

        if not self.project_id:
            raise ValueError("GCP project_id required (set GOOGLE_CLOUD_PROJECT or use a service account key file)")

        self._caller: dict[str, Any] | None = None

    @classmethod
    def from_key_file(cls, path: Path | str, project_id: str | None = None) -> GcpCredential:
        return cls(key_file=path, project_id=project_id)

    @classmethod
    def from_env(cls, project_id: str | None = None) -> GcpCredential:
        return cls(project_id=project_id)

    def credentials(self) -> Any:
        return self._credentials

    def client(self, service: str, region: str | None = None) -> Any:
        del region
        creds = self._credentials
        project = self.project_id

        if service in {"iam", "serviceaccounts"}:
            from google.cloud import iam_admin_v1

            return iam_admin_v1.IAMClient(credentials=creds)
        if service in {"resourcemanager", "projects"}:
            from google.cloud import resourcemanager_v3

            return resourcemanager_v3.ProjectsClient(credentials=creds)
        if service in {"storage", "gcs"}:
            from google.cloud import storage

            return storage.Client(project=project, credentials=creds)
        if service in {"secretmanager", "secrets"}:
            from google.cloud import secretmanager

            return secretmanager.SecretManagerServiceClient(credentials=creds)
        raise ValueError(f"Unknown GCP service: {service}")

    def get_caller_identity(self) -> dict[str, Any]:
        if self._caller is None:
            email = getattr(self._credentials, "service_account_email", None)
            if email:
                native_id = sa_native_id(email)
                kind = "ServiceAccount"
            else:
                email = getattr(self._credentials, "quota_project_id", None) or "unknown-user"
                native_id = f"gcp:user:{email}"
                kind = "User"
            self._caller = {
                "email": email,
                "native_id": native_id,
                "native_kind": kind,
                "project_id": self.project_id,
            }
        return self._caller

    def resolve_scope(self) -> ScopeBoundary:
        ident = self.get_caller_identity()
        scope_id = make_scope_id(CloudProvider.GCP, "project", self.project_id)
        return ScopeBoundary(
            provider=CloudProvider.GCP,
            scope_id=scope_id,
            display_name=f"GCP project {self.project_id}",
            properties={
                "project_id": self.project_id,
                "email": ident["email"],
                "native_id": ident["native_id"],
            },
        )

    def fingerprint(self) -> str:
        return self.get_caller_identity()["native_id"]


def sa_native_id(email: str) -> str:
    return f"gcp:serviceaccount:{email}"
