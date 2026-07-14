from __future__ import annotations

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.native_ids import canonical_native_id
from samoyed.ingest.concept_normalizer import ConceptNormalizer


def test_canonical_native_id_normalizes_lambda_and_ec2():
    lam_arn = "arn:aws:lambda:us-east-1:123:function:tool"
    ec2_arn = "arn:aws:ec2:us-east-1:123:instance/i-abc"
    assert canonical_native_id(lam_arn) == f"LambdaFunction:{lam_arn}"
    assert canonical_native_id(ec2_arn) == f"EC2Instance:{ec2_arn}"
    assert canonical_native_id(f"LambdaFunction:{lam_arn}") == f"LambdaFunction:{lam_arn}"


def test_concept_normalizer_merges_lambda_arn_aliases():
    lam_arn = "arn:aws:lambda:us-east-1:123:function:tool"
    role_arn = "arn:aws:iam::123:role/lambda-exec"
    artifacts = [
        ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id=f"LambdaFunction:{lam_arn}",
            scope_id="aws:scope:123",
            properties={"function_name": "tool"},
            evidence=Evidence("test", {}),
            confidence=ConfidenceType.EXPLICIT,
            edges=[],
        ),
        ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=role_arn,
            scope_id="aws:scope:123",
            properties={"native_kind": "Role", "arn": role_arn},
            evidence=Evidence("test", {}),
            confidence=ConfidenceType.EXPLICIT,
            edges=[
                ConceptEdge(
                    rel_type="CAN_ASSUME_ROLE",
                    target_native_id=lam_arn,
                    props={"action": "sts:AssumeRole"},
                )
            ],
        ),
    ]
    builder = GraphBuilder("alias-test")
    ConceptNormalizer().ingest(builder, artifacts)
    lam_nodes = [
        nid
        for nid, n in builder.snapshot.nodes.items()
        if n.props.get("native_id") in {lam_arn, f"LambdaFunction:{lam_arn}"}
        or nid == lam_arn
    ]
    assert len(lam_nodes) == 1
