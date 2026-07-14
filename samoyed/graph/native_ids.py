from __future__ import annotations

import re

from samoyed.cloud.concepts import ConceptType


def canonical_native_id(ref: str) -> str:
    """Normalize AWS refs so grants and inventory share one native id."""
    if not ref:
        return ref
    if ref.startswith(("S3Bucket:", "Secret:", "LambdaFunction:", "EC2Instance:")):
        return ref
    if ref.startswith("arn:aws:lambda:") and ":function:" in ref:
        return f"LambdaFunction:{ref}"
    if ref.startswith("arn:aws:ec2:") and ":instance/" in ref:
        return f"EC2Instance:{ref}"
    if ref.startswith("arn:aws:secretsmanager:"):
        return f"Secret:{ref}"
    if ref.startswith("arn:aws:s3:"):
        match = re.search(r":::([^/*]+)", ref) or re.search(r"bucket/([^/*]+)", ref)
        if match:
            return f"S3Bucket:{match.group(1)}"
    return ref


def infer_concept_type(native_id: str) -> ConceptType | None:
    if not native_id:
        return None
    if native_id.startswith(("LambdaFunction:", "EC2Instance:")):
        return ConceptType.RUNTIME_BINDING
    if native_id.startswith(("S3Bucket:", "Secret:")):
        return ConceptType.DATA_STORE if native_id.startswith("S3Bucket:") else ConceptType.SECRET_STORE
    if native_id.startswith("arn:aws:iam:"):
        return ConceptType.IDENTITY
    if native_id.startswith("arn:aws:lambda:"):
        return ConceptType.RUNTIME_BINDING
    if native_id.startswith("arn:aws:ec2:") and ":instance/" in native_id:
        return ConceptType.RUNTIME_BINDING
    if native_id.startswith("arn:aws:eks:"):
        return ConceptType.ORCHESTRATION_SCOPE
    return None
