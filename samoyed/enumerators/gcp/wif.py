"""Enumerate GCP Workload Identity Federation pools/providers → SA bindings."""

from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.gcp import sa_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.gcp.helpers import call_gcp


class GcpWifEnumerator:
    concept = ConceptType.TRUST
    name = "gcp-wif"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        project = str(ctx.scope.properties.get("project_id") or "")
        if not project:
            return
        cred = ctx.credentials
        try:
            from google.auth.transport.requests import AuthorizedSession
        except ImportError:
            return
        try:
            session = AuthorizedSession(cred.credentials())  # type: ignore[attr-defined]
        except Exception:
            return

        parent = f"projects/{project}/locations/global"
        pools_url = f"https://iam.googleapis.com/v1/{parent}/workloadIdentityPools"
        pools = _list_items(session, pools_url, "workloadIdentityPools")
        for pool in pools:
            pool_name = str(pool.get("name") or "")
            if not pool_name:
                continue
            providers_url = f"https://iam.googleapis.com/v1/{pool_name}/providers"
            providers = _list_items(session, providers_url, "workloadIdentityPoolProviders")
            for provider in providers:
                provider_name = str(provider.get("name") or "")
                issuer = str(
                    (provider.get("oidc") or {}).get("issuerUri")
                    or (provider.get("aws") or {}).get("accountId")
                    or ""
                )
                yield ConceptArtifact(
                    concept_type=ConceptType.TRUST,
                    provider=CloudProvider.GCP,
                    native_id=f"gcp:wif-provider:{provider_name}",
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "native_kind": "WorkloadIdentityPoolProvider",
                        "pool": pool_name,
                        "provider": provider_name,
                        "issuer": issuer,
                        "display_name": provider.get("displayName") or provider_name,
                    },
                    evidence=Evidence("iam.workloadIdentityPoolProviders.list", {"name": provider_name}),
                )

        # SA IAM: workloadIdentityUser members → CAN_ASSUME_ROLE (mechanism=wif)
        iam = cred.client("iam")  # type: ignore[attr-defined]
        sas = call_gcp(
            ctx,
            operation="iam.serviceAccounts.list",
            call=lambda: list(iam.list_service_accounts(request={"parent": f"projects/{project}"})),
        )
        if not sas:
            return
        for sa in sas:
            email = getattr(sa, "email", None)
            name = getattr(sa, "name", None)
            if not email or not name:
                continue
            policy = call_gcp(
                ctx,
                operation="iam.serviceAccounts.getIamPolicy",
                call=lambda resource=name: iam.get_iam_policy(request={"resource": resource}),
            )
            if not policy:
                continue
            for binding in getattr(policy, "bindings", []) or []:
                if getattr(binding, "role", "") != "roles/iam.workloadIdentityUser":
                    continue
                target = sa_native_id(email)
                for member in list(getattr(binding, "members", []) or []):
                    if not str(member).startswith("principal"):
                        continue
                    yield ConceptArtifact(
                        concept_type=ConceptType.TRUST,
                        provider=CloudProvider.GCP,
                        native_id=f"gcp:wif:{member}->{email}",
                        scope_id=ctx.scope.scope_id,
                        properties={
                            "mechanism": "wif",
                            "member": member,
                            "service_account": email,
                        },
                        evidence=Evidence(
                            "iam.serviceAccounts.getIamPolicy",
                            {"role": "roles/iam.workloadIdentityUser", "sa": email},
                        ),
                        edges=[
                            ConceptEdge(
                                rel_type="CAN_ASSUME_ROLE",
                                src_native_id=f"gcp:wif-principal:{member}",
                                target_native_id=target,
                                target_concept_type=ConceptType.IDENTITY,
                                props={
                                    "mechanism": "wif",
                                    "member": member,
                                    "role": "roles/iam.workloadIdentityUser",
                                },
                                confidence=ConfidenceType.EXPLICIT,
                            )
                        ],
                    )


def _list_items(session: object, url: str, key: str) -> list[dict]:
    try:
        resp = session.get(url, timeout=30)  # type: ignore[attr-defined]
        if getattr(resp, "status_code", 500) >= 400:
            return []
        data = resp.json()
        return list(data.get(key) or [])
    except Exception:
        return []
