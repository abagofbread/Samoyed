"""AWS IAM Access Analyzer findings → inbound CAN_ACCESS / READS edges.

Distinct from identity-policy enum + FEEDS:
- IAM entitlements: what a principal *may* do (outbound capability).
- FEEDS: producer scope ∩ consumer scope among already-emitted edges.
- Access Analyzer: AWS-evaluated *who can reach this resource* (often external /
  cross-account principals), attached as inbound edges on crown jewels.
"""

from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.contracts import ConceptEnumerator
from samoyed.enumerators.runner import paginate_call
from samoyed.graph.resource_scope import resolve_policy_resource


class AwsAccessAnalyzerEnumerator:
    concept = ConceptType.DATA_STORE
    name = "aws-access-analyzer"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        aa = cred.client("accessanalyzer")  # type: ignore[attr-defined]
        analyzers = paginate_call(
            ctx,
            operation="accessanalyzer:ListAnalyzers",
            call=lambda: aa.list_analyzers(),
        )
        if not analyzers:
            return

        active = [a for a in analyzers.get("analyzers", []) if a.get("status") == "ACTIVE"]
        if not active:
            # Fall back to any listed analyzer (ACCOUNT type may still have findings)
            active = list(analyzers.get("analyzers") or [])

        for analyzer in active:
            name = analyzer.get("name") or analyzer.get("arn", "").rsplit("/", 1)[-1]
            if not name:
                continue
            findings_resp = paginate_call(
                ctx,
                operation="accessanalyzer:ListFindings",
                call=lambda arn=analyzer.get("arn"), n=name: aa.list_findings(
                    analyzerArn=arn or n,
                    filter={"status": {"eq": ["ACTIVE"]}},
                    maxResults=50,
                ),
            )
            if not findings_resp:
                continue

            for finding in findings_resp.get("findings", []) or []:
                yield from _finding_artifacts(ctx, finding, analyzer_name=name)


def _finding_artifacts(
    ctx: EnumContext,
    finding: dict[str, Any],
    *,
    analyzer_name: str,
) -> Iterator[ConceptArtifact]:
    resource = finding.get("resource") or finding.get("resourceArn") or ""
    if not resource:
        return

    # Normalize resource → Samoyed native id
    rtype = _resource_type_hint(resource, finding.get("resourceType"))
    native_id, _scope = resolve_policy_resource(resource, rtype)
    concept = _concept_for_rtype(rtype)

    principal = _principal_from_finding(finding)
    if not principal:
        return

    action = _primary_action(finding)
    rel = "READS" if action and any(x in action.lower() for x in ("get", "list", "read", "decrypt")) else "CAN_ACCESS"
    if action and any(x in action.lower() for x in ("put", "write", "delete", "create", "update")):
        rel = "WRITES" if "delete" not in action.lower() else "DELETES"

    is_external = bool(finding.get("isPublic")) or _looks_external(
        principal, resource, finding.get("resourceOwnerAccount")
    )

    edges = [
        ConceptEdge(
            rel_type=rel,
            src_native_id=principal,
            target_native_id=native_id,
            target_concept_type=concept,
            props={
                "resource": resource,
                "resource_type": rtype or "Unknown",
                "action": action,
                "source": "access-analyzer",
                "discovered_via": "access-analyzer",
                "analyzer": analyzer_name,
                "finding_id": finding.get("id") or finding.get("findingId"),
                "is_public": bool(finding.get("isPublic")),
                "is_external": is_external,
            },
            confidence=ConfidenceType.EXPLICIT,
        )
    ]

    # Emit lightweight principal stub so the edge resolves even outside identity enum.
    yield ConceptArtifact(
        concept_type=ConceptType.IDENTITY,
        provider=CloudProvider.AWS,
        native_id=principal,
        scope_id=ctx.scope.scope_id,
        properties={
            "native_kind": _principal_kind(principal),
            "arn": principal if principal.startswith("arn:") else None,
            "discovered_via": "access-analyzer",
            "display_name": principal,
        },
        evidence=Evidence(
            "accessanalyzer:ListFindings",
            {"principal": principal, "resource": resource},
        ),
        confidence=ConfidenceType.EXPLICIT,
        edges=[],
    )

    yield ConceptArtifact(
        concept_type=concept,
        provider=CloudProvider.AWS,
        native_id=native_id,
        scope_id=ctx.scope.scope_id,
        properties={
            "resource_type": rtype or "Unknown",
            "arn": resource if resource.startswith("arn:") else None,
            "discovered_via": "access-analyzer",
            "access_analyzer_finding": True,
        },
        evidence=Evidence(
            "accessanalyzer:ListFindings",
            {
                "finding_id": finding.get("id") or finding.get("findingId"),
                "resource": resource,
                "principal": principal,
            },
        ),
        confidence=ConfidenceType.EXPLICIT,
        edges=edges,
    )


def _principal_from_finding(finding: dict[str, Any]) -> str | None:
    principal = finding.get("principal")
    if isinstance(principal, dict):
        # {"AWS": "arn:...", "Federated": "...", "CanonicalUser": "..."}
        for key in ("AWS", "Federated", "CanonicalUser"):
            val = principal.get(key)
            if isinstance(val, str) and val:
                return "*" if val == "*" else val
            if isinstance(val, list) and val:
                return str(val[0])
        # Sometimes nested under "AWS": ["arn"]
    if isinstance(principal, str) and principal:
        return principal

    # Alternative shapes
    for key in ("principalArn", "actor", "externalPrincipal"):
        val = finding.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _primary_action(finding: dict[str, Any]) -> str | None:
    actions = finding.get("action") or finding.get("actions") or []
    if isinstance(actions, str):
        return actions
    if isinstance(actions, list) and actions:
        return str(actions[0])
    return None


def _resource_type_hint(resource: str, aa_type: Any) -> str | None:
    if isinstance(aa_type, str) and aa_type:
        mapping = {
            "AWS::S3::Bucket": "S3Bucket",
            "AWS::SecretsManager::Secret": "Secret",
            "AWS::KMS::Key": "KMSKey",
            "AWS::SQS::Queue": "SQSQueue",
            "AWS::Lambda::Function": "LambdaFunction",
            "AWS::IAM::Role": "Role",
            "AWS::ECR::Repository": "ECRRepository",
            "AWS::S3Express::DirectoryBucket": "S3Bucket",
        }
        if aa_type in mapping:
            return mapping[aa_type]
    if ":s3:::" in resource or resource.startswith("arn:aws:s3:"):
        return "S3Bucket"
    if ":secretsmanager:" in resource:
        return "Secret"
    if ":kms:" in resource:
        return "KMSKey"
    if ":ecr:" in resource:
        return "ECRRepository"
    if ":lambda:" in resource:
        return "LambdaFunction"
    if ":iam:" in resource and ":role/" in resource:
        return "Role"
    return None


def _concept_for_rtype(rtype: str | None) -> ConceptType:
    if rtype in {"Secret", "SSMParameter"}:
        return ConceptType.SECRET_STORE
    if rtype == "ECRRepository":
        return ConceptType.REGISTRY_STORE
    if rtype in {"Role", "User"}:
        return ConceptType.IDENTITY
    if rtype == "LambdaFunction":
        return ConceptType.RUNTIME_BINDING
    return ConceptType.DATA_STORE


def _principal_kind(principal: str) -> str:
    if principal == "*":
        return "Anonymous"
    if ":user/" in principal:
        return "User"
    if ":role/" in principal:
        return "Role"
    if ":root" in principal:
        return "Account"
    if principal.startswith("arn:aws:iam::") and principal.endswith(":root"):
        return "Account"
    return "ExternalPrincipal"


def _looks_external(principal: str, resource: str, resource_owner_account: Any = None) -> bool:
    if principal in {"*", "Anonymous"}:
        return True

    def acct(arn: str) -> str | None:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 and str(parts[4]).isdigit() else None

    pa = acct(principal)
    ra = acct(resource)
    owner = str(resource_owner_account) if resource_owner_account else None
    if owner and owner.isdigit():
        ra = ra or owner
    if pa and ra and pa != ra:
        return True
    # Account-root principals without matching embedded resource account are treated external
    if pa and principal.endswith(":root") and (not ra or pa != ra):
        return True
    return False
