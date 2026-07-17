"""Enumerate AWS Organizations SCPs that apply to the caller's account.

Best-effort: missing Organizations access → no clamp (same as unknown). Management
accounts are marked ``scp_exempt``. Member accounts get ScopeBoundary props used by
``collect_principal_actions`` to intersect identity grants with SCP Allow/Deny.
"""

from __future__ import annotations

from typing import Any, Iterator
from urllib.parse import unquote

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.cloud.providers import make_scope_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.contracts import ConceptEnumerator
from samoyed.enumerators.runner import paginate_call
from samoyed.policy.scp import (
    ScpConstraints,
    ScpDocument,
    merge_scp_documents,
    parse_scp_document,
    scp_props_for_scope,
)


# Soft: account not in an org / orgs not enabled / not a member.
_ORGS_SOFT = frozenset(
    {
        "AWSOrganizationsNotInUseException",
        "AWSAccountNotRegisteredException",
        "AccountNotRegisteredException",
        "OrganizationNotFoundException",
        "TargetNotFoundException",
        "PolicyNotFoundException",
        "ConstraintViolationException",
        "AccessDeniedException",
    }
)


class AwsOrganizationsScpEnumerator:
    concept = ConceptType.SCOPE_BOUNDARY
    name = "aws-organizations-scp"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        ident = cred.get_caller_identity()  # type: ignore[attr-defined]
        account = str(ident["Account"])
        scope_id = make_scope_id(CloudProvider.AWS, "account", account)

        orgs = cred.client("organizations")  # type: ignore[attr-defined]
        org_resp = paginate_call(
            ctx,
            operation="organizations:DescribeOrganization",
            call=lambda: orgs.describe_organization(),
            soft_errors=_ORGS_SOFT,
        )
        if not org_resp:
            return

        org = org_resp.get("Organization") or {}
        management_account = str(org.get("MasterAccountId") or org.get("ManagementAccountId") or "")
        org_id = str(org.get("Id") or "")

        if management_account and account == management_account:
            props = scp_props_for_scope(
                ScpConstraints(exempt=True, policy_names=("management-account",))
            )
            yield ConceptArtifact(
                concept_type=ConceptType.SCOPE_BOUNDARY,
                provider=CloudProvider.AWS,
                native_id=scope_id,
                scope_id=scope_id,
                properties={
                    "account_id": account,
                    "organization_id": org_id,
                    "management_account_id": management_account,
                    "display_name": f"AWS account {account} (org management — SCP exempt)",
                    **props,
                },
                evidence=Evidence(
                    "organizations:DescribeOrganization",
                    {"account": account, "scp_exempt": True},
                ),
                confidence=ConfidenceType.EXPLICIT,
            )
            return

        target_ids = _hierarchy_targets(ctx, orgs, account)
        docs = _policies_for_targets(ctx, orgs, target_ids)
        constraints = merge_scp_documents(docs)
        props = scp_props_for_scope(constraints)
        if not props and not docs:
            # In an org but no readable SCPs — still emit scope with org metadata.
            props = {"scp_exempt": False, "scp_allow_sets": [], "scp_deny_actions": []}

        yield ConceptArtifact(
            concept_type=ConceptType.SCOPE_BOUNDARY,
            provider=CloudProvider.AWS,
            native_id=scope_id,
            scope_id=scope_id,
            properties={
                "account_id": account,
                "organization_id": org_id,
                "management_account_id": management_account or None,
                "display_name": f"AWS account {account}",
                "scp_target_ids": target_ids,
                **props,
            },
            evidence=Evidence(
                "organizations:ListPoliciesForTarget",
                {
                    "account": account,
                    "policy_ids": list(constraints.policy_ids),
                    "policy_names": list(constraints.policy_names),
                    "targets": target_ids,
                },
            ),
            confidence=ConfidenceType.EXPLICIT,
        )


def _hierarchy_targets(ctx: EnumContext, orgs: Any, account_id: str) -> list[str]:
    """Account + parent OUs + root (closest → root)."""
    targets = [account_id]
    current = account_id
    seen: set[str] = {account_id}
    for _ in range(12):
        resp = paginate_call(
            ctx,
            operation="organizations:ListParents",
            call=lambda c=current: orgs.list_parents(ChildId=c),
            soft_errors=_ORGS_SOFT,
        )
        if not resp:
            break
        parents = resp.get("Parents") or []
        if not parents:
            break
        parent = parents[0]
        pid = str(parent.get("Id") or "")
        ptype = str(parent.get("Type") or "")
        if not pid or pid in seen:
            break
        seen.add(pid)
        targets.append(pid)
        current = pid
        if ptype.upper() == "ROOT":
            break
    return targets


def _policies_for_targets(ctx: EnumContext, orgs: Any, target_ids: list[str]) -> list[ScpDocument]:
    docs: list[ScpDocument] = []
    seen_policy: set[str] = set()
    for target in target_ids:
        resp = paginate_call(
            ctx,
            operation="organizations:ListPoliciesForTarget",
            call=lambda t=target: orgs.list_policies_for_target(
                TargetId=t,
                Filter="SERVICE_CONTROL_POLICY",
            ),
            soft_errors=_ORGS_SOFT,
        )
        if not resp:
            continue
        for pol in resp.get("Policies") or []:
            pid = str(pol.get("Id") or "")
            if not pid or pid in seen_policy:
                continue
            seen_policy.add(pid)
            detail = paginate_call(
                ctx,
                operation="organizations:DescribePolicy",
                call=lambda p=pid: orgs.describe_policy(PolicyId=p),
                soft_errors=_ORGS_SOFT,
            )
            if not detail:
                continue
            body = (detail.get("Policy") or {}).get("Content") or pol.get("Content") or "{}"
            if isinstance(body, str):
                try:
                    body = unquote(body)
                except Exception:
                    pass
            name = str((detail.get("Policy") or {}).get("PolicySummary", {}).get("Name") or pol.get("Name") or pid)
            docs.append(parse_scp_document(body, policy_id=pid, name=name))
    return docs
