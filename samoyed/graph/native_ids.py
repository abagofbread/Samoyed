from __future__ import annotations

import re

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.resource_scope import resolve_policy_resource


def canonical_native_id(ref: str) -> str:
    """Normalize AWS refs so grants and inventory share one native id."""
    if not ref:
        return ref
    # Unwrap typed wrappers that still contain raw ARNs/patterns
    for prefix in ("S3Bucket:", "Secret:", "ECRRepository:", "SSMParameter:"):
        if ref.startswith(prefix):
            rest = ref[len(prefix) :]
            if rest.startswith("arn:aws:") or rest == "*":
                nid, _scope = resolve_policy_resource(rest, prefix.rstrip(":"))
                return nid
            if prefix == "S3Bucket:" and ("/" in rest or rest.endswith("*")):
                nid, _scope = resolve_policy_resource(rest, "S3Bucket")
                return nid
            return ref

    if ref.startswith(("LambdaFunction:", "EC2Instance:")):
        return ref
    if ref.startswith("arn:aws:lambda:") and ":function:" in ref:
        return f"LambdaFunction:{ref}"
    if ref.startswith("arn:aws:ec2:") and ":instance/" in ref:
        return f"EC2Instance:{ref}"
    if ref.startswith("arn:aws:secretsmanager:"):
        return f"Secret:{ref}"
    if ref.startswith("arn:aws:ecr:") and ":repository/" in ref:
        nid, _ = resolve_policy_resource(ref, "ECRRepository")
        return nid
    if ref.startswith("arn:aws:s3:"):
        match = re.search(r":::([^/*]+)", ref) or re.search(r"bucket/([^/*]+)", ref)
        if match:
            return f"S3Bucket:{match.group(1)}"
    if ref.startswith("arn:aws:ssm:") and ":parameter" in ref:
        nid, _ = resolve_policy_resource(ref, "SSMParameter")
        return nid
    return ref


def infer_concept_type(native_id: str) -> ConceptType | None:
    if not native_id:
        return None
    if native_id.startswith(("LambdaFunction:", "EC2Instance:")):
        return ConceptType.RUNTIME_BINDING
    if native_id.startswith("S3Bucket:"):
        return ConceptType.DATA_STORE
    if native_id.startswith("Secret:") or native_id.startswith("SSMParameter:"):
        return ConceptType.SECRET_STORE
    if native_id.startswith("ECRRepository:"):
        return ConceptType.REGISTRY_STORE
    if native_id.startswith("arn:aws:iam:"):
        return ConceptType.IDENTITY
    if native_id.startswith("arn:aws:lambda:"):
        return ConceptType.RUNTIME_BINDING
    if native_id.startswith("arn:aws:ec2:") and ":instance/" in native_id:
        return ConceptType.RUNTIME_BINDING
    if native_id.startswith("arn:aws:eks:"):
        return ConceptType.ORCHESTRATION_SCOPE
    if native_id.startswith("arn:aws:ecr:"):
        return ConceptType.REGISTRY_STORE
    return None
