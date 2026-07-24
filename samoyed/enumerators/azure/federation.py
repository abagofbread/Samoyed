"""Enumerate Azure federated identity credentials (WIF / OIDC) on managed identities."""

from __future__ import annotations

import re
from typing import Any, Iterator
from urllib.parse import urlparse

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.azure import mi_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.azure.helpers import call_azure
from samoyed.enumerators.azure.targets import resource_group_from_id

_AWS_STS_ACCOUNT_RE = re.compile(
    r"(?:https?://)?sts\.amazonaws\.com/(\d{12})", re.I
)
_AWS_OIDC_ACCOUNT_RE = re.compile(r"oidc-provider/.*?[/:.](\d{12})", re.I)


class AzureFederationEnumerator:
    concept = ConceptType.TRUST
    name = "azure-federation"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        yield from _federated_on_user_assigned_mis(ctx)
        yield from _federated_on_apps_graph(ctx)


def _federated_on_user_assigned_mis(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    try:
        msi = cred.client("msi")  # type: ignore[attr-defined]
    except ImportError:
        return

    identities = call_azure(
        ctx,
        operation="msi.userAssignedIdentities.listBySubscription",
        call=lambda: list(msi.user_assigned_identities.list_by_subscription()),
    )
    if not identities:
        return

    for identity in identities:
        principal_id = getattr(identity, "principal_id", None)
        name = getattr(identity, "name", None)
        arm_id = getattr(identity, "id", None)
        rg = resource_group_from_id(arm_id)
        if not principal_id or not name or not rg:
            continue
        target = mi_native_id(str(principal_id))

        if not hasattr(msi, "federated_identity_credentials"):
            return
        try:
            creds = call_azure(
                ctx,
                operation=f"msi.federatedIdentityCredentials.list:{name}",
                call=lambda rg=rg, name=name: list(
                    msi.federated_identity_credentials.list(rg, name)
                ),
            )
        except (AttributeError, TypeError):
            continue
        if not creds:
            continue

        for fic in creds:
            issuer = str(getattr(fic, "issuer", None) or "")
            subject = str(getattr(fic, "subject", None) or "")
            fic_name = str(getattr(fic, "name", None) or "fic")
            foreign = _foreign_from_issuer(issuer, subject)
            mechanism = "wif" if foreign.get("account_id") or foreign.get("project_id") else "oidc-federation"
            src = f"azure:oidc:{issuer}:{subject}" if issuer or subject else f"azure:fic:{name}:{fic_name}"
            props: dict[str, Any] = {
                "mechanism": mechanism,
                "issuer": issuer,
                "subject": subject,
                "audiences": list(getattr(fic, "audiences", None) or []),
                **foreign,
            }
            yield ConceptArtifact(
                concept_type=ConceptType.TRUST,
                provider=CloudProvider.AZURE,
                native_id=f"azure:fic:{name}:{fic_name}",
                scope_id=ctx.scope.scope_id,
                properties={
                    "native_kind": "FederatedIdentityCredential",
                    "managed_identity": name,
                    "principal_id": str(principal_id),
                    **props,
                },
                evidence=Evidence(
                    "msi.federatedIdentityCredentials.list",
                    {"identity": name, "issuer": issuer, "subject": subject},
                ),
                edges=[
                    ConceptEdge(
                        rel_type="CAN_ASSUME_ROLE",
                        src_native_id=src,
                        target_native_id=target,
                        target_concept_type=ConceptType.IDENTITY,
                        props=props,
                        confidence=ConfidenceType.EXPLICIT,
                    )
                ],
            )


def _federated_on_apps_graph(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    """Best-effort Microsoft Graph listing of application federated identity credentials."""
    cred = ctx.credentials
    try:
        token = cred.credential().get_token("https://graph.microsoft.com/.default")  # type: ignore[attr-defined]
    except Exception:
        return

    try:
        import urllib.request
        import json
    except ImportError:
        return

    headers = {"Authorization": f"Bearer {token.token}", "Content-Type": "application/json"}
    # Applications with federatedIdentityCredentials — expand where supported
    url = (
        "https://graph.microsoft.com/v1.0/applications"
        "?$select=id,appId,displayName,federatedIdentityCredentials"
        "&$top=50"
    )
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return

    for app in data.get("value") or []:
        app_id = str(app.get("appId") or app.get("id") or "")
        display = str(app.get("displayName") or app_id)
        for fic in app.get("federatedIdentityCredentials") or []:
            issuer = str(fic.get("issuer") or "")
            subject = str(fic.get("subject") or "")
            fic_name = str(fic.get("name") or "fic")
            foreign = _foreign_from_issuer(issuer, subject)
            mechanism = (
                "wif"
                if foreign.get("account_id") or foreign.get("project_id")
                else "oidc-federation"
            )
            target = f"azure:serviceprincipal:{app_id}"
            src = f"azure:oidc:{issuer}:{subject}"
            props: dict[str, Any] = {
                "mechanism": mechanism,
                "issuer": issuer,
                "subject": subject,
                **foreign,
            }
            yield ConceptArtifact(
                concept_type=ConceptType.TRUST,
                provider=CloudProvider.AZURE,
                native_id=f"azure:app-fic:{app_id}:{fic_name}",
                scope_id=ctx.scope.scope_id,
                properties={
                    "native_kind": "ApplicationFederatedIdentityCredential",
                    "app_id": app_id,
                    "display_name": display,
                    **props,
                },
                evidence=Evidence(
                    "graph.applications.federatedIdentityCredentials",
                    {"appId": app_id, "issuer": issuer},
                ),
                edges=[
                    ConceptEdge(
                        rel_type="CAN_ASSUME_ROLE",
                        src_native_id=src,
                        target_native_id=target,
                        target_concept_type=ConceptType.IDENTITY,
                        props=props,
                        confidence=ConfidenceType.EXPLICIT,
                    )
                ],
            )


def _foreign_from_issuer(issuer: str, subject: str = "") -> dict[str, str]:
    """Detect foreign cloud account/project from OIDC issuer (and subject hints)."""
    out: dict[str, str] = {}
    text = f"{issuer} {subject}"
    m = _AWS_STS_ACCOUNT_RE.search(text) or _AWS_OIDC_ACCOUNT_RE.search(text)
    if m:
        out["account_id"] = m.group(1)
        return out
    if "sts.amazonaws.com" in issuer.lower() or "amazonaws.com" in issuer.lower():
        # Subject often encodes account: role ARN or system:serviceaccount
        arn_m = re.search(r"arn:aws:iam::(\d{12}):", text)
        if arn_m:
            out["account_id"] = arn_m.group(1)
            return out
    if "accounts.google.com" in issuer.lower():
        # Subject may be a GCP SA email → project from email domain prefix
        sa_m = re.search(
            r"([a-z0-9-]+)@[a-z0-9-]+\.iam\.gserviceaccount\.com", subject, re.I
        )
        if sa_m:
            # project is between @ and .iam
            full = re.search(
                r"@([a-z0-9-]+)\.iam\.gserviceaccount\.com", subject, re.I
            )
            if full:
                out["project_id"] = full.group(1)
        parsed = urlparse(issuer if "://" in issuer else f"https://{issuer}")
        # Some Google issuers embed project in path
        parts = [p for p in parsed.path.split("/") if p]
        if parts and "project_id" not in out:
            out["project_id"] = parts[-1]
        if "project_id" not in out:
            out["project_id"] = ""
        if out.get("project_id") == "":
            out.pop("project_id", None)
    return out
