from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder


@dataclass
class HostCredentialStore:
    """Cached cloud credential on a compromised host (~/.aws, SSO cache, kubeconfig, etc.)."""

    identity_native_id: str
    store_type: str
    path_hint: str = ""
    provider: CloudProvider | None = None


@dataclass
class HostInteractiveSession:
    """Logged-in user session harvestable via LSASS / mimikatz / token theft."""

    identity_native_id: str
    session_type: str = "interactive"
    provider: CloudProvider | None = None
    notes: str = ""


@dataclass
class HostPivotSpec:
    host_native_id: str
    display_name: str = "Compromised workstation"
    interactive_sessions: list[HostInteractiveSession] = field(default_factory=list)
    credential_stores: list[HostCredentialStore] = field(default_factory=list)
    is_scenario_start: bool = True


# Well-known credential locations (HackTricks / red-team playbooks)
COMMON_HOST_STORES: tuple[HostCredentialStore, ...] = (
    HostCredentialStore(
        "aws:cached-profile:*",
        "aws-cli-credentials",
        path_hint="~/.aws/credentials",
        provider=CloudProvider.AWS,
    ),
    HostCredentialStore(
        "aws:sso-cache:*",
        "aws-sso-cache",
        path_hint="~/.aws/sso/cache/*.json",
        provider=CloudProvider.AWS,
    ),
    HostCredentialStore(
        "gcp:adc:*",
        "gcp-application-default",
        path_hint="~/.config/gcloud/application_default_credentials.json",
        provider=CloudProvider.GCP,
    ),
    HostCredentialStore(
        "azure:cli-cache:*",
        "azure-cli-token-cache",
        path_hint="~/.azure/msal_token_cache.json",
        provider=CloudProvider.AZURE,
    ),
    HostCredentialStore(
        "kubernetes:kubeconfig:*",
        "kubeconfig",
        path_hint="~/.kube/config",
        provider=CloudProvider.KUBERNETES,
    ),
)


def apply_host_pivot(builder: GraphBuilder, spec: HostPivotSpec) -> str:
    """Add compromised-host node and pivot edges into the cloud identity graph."""
    host_id = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id=spec.host_native_id,
        props={
            "native_kind": "CompromisedHost",
            "display_name": spec.display_name,
            "is_scenario_start": spec.is_scenario_start,
            "pivot_surface": "host",
        },
    )

    for session in spec.interactive_sessions:
        identity_id = _ensure_identity(builder, session.identity_native_id, session.provider)
        builder.add_edge(
            src_id=host_id,
            rel_type="LOGGED_IN_AS",
            dst_id=identity_id,
            props={
                "session_type": session.session_type,
                "harvest_method": "interactive-token-theft",
                "notes": session.notes or "LSASS / mimikatz / token duplication",
                "confidence": "explicit",
            },
        )
        # Synthetic capability — host compromise unlocks cached SSO / refresh tokens
        builder.add_edge(
            src_id=host_id,
            rel_type="CAN_STEAL_CREDS_FROM",
            dst_id=identity_id,
            props={
                "action": "host:interactive-session",
                "confidence": "explicit",
            },
        )

    for store in spec.credential_stores:
        identity_id = _ensure_identity(builder, store.identity_native_id, store.provider)
        builder.add_edge(
            src_id=host_id,
            rel_type="STORES_CREDS_FOR",
            dst_id=identity_id,
            props={
                "store_type": store.store_type,
                "path_hint": store.path_hint,
                "confidence": "explicit",
            },
        )
        builder.add_edge(
            src_id=host_id,
            rel_type="CAN_STEAL_CREDS_FROM",
            dst_id=identity_id,
            props={
                "action": "host:credential-store",
                "store_type": store.store_type,
                "confidence": "explicit",
            },
        )

    builder.link_session(host_id)
    return host_id


def _ensure_identity(
    builder: GraphBuilder,
    native_id: str,
    provider: CloudProvider | None,
) -> str:
    kind = _infer_kind(native_id)
    props: dict[str, Any] = {
        "native_kind": kind,
        "display_name": native_id,
    }
    if provider:
        props["provider"] = provider.value
    if native_id.startswith("arn:aws:"):
        props["arn"] = native_id
    if "@corp.com" in native_id or native_id.startswith("azure:user:"):
        props.setdefault("provider", CloudProvider.AZURE.value)

    return builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=native_id,
        props=props,
    )


def _infer_kind(native_id: str) -> str:
    if ":role/" in native_id:
        return "Role"
    if ":user/" in native_id or native_id.startswith("gcp:user:") or native_id.startswith("azure:user:"):
        return "User"
    if "serviceaccount" in native_id:
        return "ServiceAccount"
    return "Identity"
