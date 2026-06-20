from __future__ import annotations

from samoyed.cloud.concepts import CloudProvider
from samoyed.cloud.providers import make_scope_id
from samoyed.credentials.protocol import CloudCredential, ScopeBoundary


def resolve_scope_best_effort(credentials: CloudCredential) -> ScopeBoundary:
    """Resolve scope when IAM/admin APIs may be unavailable."""
    try:
        return credentials.resolve_scope()
    except Exception:
        pass

    provider = credentials.provider
    if provider == CloudProvider.AWS:
        native_id = _aws_caller_fallback(credentials)
        account = "unknown"
        try:
            ident = credentials.get_caller_identity()  # type: ignore[attr-defined]
            account = ident.get("Account", account)
            native_id = ident.get("Arn", native_id)
        except Exception:
            pass
        return ScopeBoundary(
            provider=provider,
            scope_id=make_scope_id(provider, "account", account),
            display_name=f"AWS account {account} (probe)",
            properties={"account_id": account, "native_id": native_id, "arn": native_id, "probe_mode": True},
        )

    if provider == CloudProvider.GCP:
        project = getattr(credentials, "project_id", None) or "unknown"
        native_id = f"gcp:unknown:{project}"
        try:
            ident = credentials.get_caller_identity()  # type: ignore[attr-defined]
            native_id = ident.get("native_id", native_id)
        except Exception:
            pass
        return ScopeBoundary(
            provider=provider,
            scope_id=make_scope_id(provider, "project", project),
            display_name=f"GCP project {project} (probe)",
            properties={"project_id": project, "native_id": native_id, "probe_mode": True},
        )

    if provider == CloudProvider.AZURE:
        sub = getattr(credentials, "subscription_id", None) or "unknown"
        native_id = "azure:unknown:principal"
        try:
            ident = credentials.get_caller_identity()  # type: ignore[attr-defined]
            native_id = ident.get("native_id", native_id)
        except Exception:
            pass
        return ScopeBoundary(
            provider=provider,
            scope_id=make_scope_id(provider, "subscription", sub),
            display_name=f"Azure subscription {sub[:8]}… (probe)",
            properties={"subscription_id": sub, "native_id": native_id, "probe_mode": True},
        )

    return ScopeBoundary(
        provider=provider,
        scope_id=f"{provider.value}:scope:unknown",
        display_name="Unknown scope (probe)",
        properties={"native_id": f"{provider.value}:unknown", "probe_mode": True},
    )


def _aws_caller_fallback(credentials: CloudCredential) -> str:
    session = getattr(credentials, "_session", None)
    if session is None:
        return "aws:unknown:principal"
    creds = session.get_credentials()
    if creds and creds.access_key:
        return f"aws:access-key:{creds.access_key}"
    return "aws:unknown:principal"


def caller_native_id(scope: ScopeBoundary) -> str:
    return scope.properties.get("native_id") or scope.properties.get("arn") or "unknown:principal"
