"""CI/CD substrate, shared-env coupling, mechanism markings, static hosting."""

from __future__ import annotations

from samoyed.attack.resource_pivot import enrich_resource_pivots
from samoyed.attack.shared_env import enrich_shared_environments, list_resource_consumers
from samoyed.attack.surface import enrich_attack_surface, _is_ssrf_hypothesis
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.enumerators.aws.cicd import _codebuild_artifact, _codepipeline_artifact
from samoyed.enumerators.aws.static_hosting import _bucket_from_origin_domain
from samoyed.enumerators.aws.tags import canonicalize_environment, environment_from_tags
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.markings import COMPROMISE_MECHANISM, apply_marking, is_high_value
from samoyed.path_engine.search import find_attack_paths


def test_codebuild_writes_artifact_bucket():
    project = {
        "name": "corp-app-dev-build",
        "arn": "arn:aws:codebuild:us-east-1:1:project/corp-app-dev-build",
        "serviceRole": "arn:aws:iam::1:role/dev-build",
        "artifacts": {"type": "S3", "location": "corp-dev-artifacts"},
        "source": {"type": "S3", "location": "corp-dev-artifacts/source.zip"},
        "environment": {
            "image": "aws/codebuild/standard:7.0",
            "environmentVariables": [
                {
                    "name": "DB_SECRET",
                    "type": "SECRETS_MANAGER",
                    "value": "arn:aws:secretsmanager:us-east-1:1:secret:ci/db-AbCdEf",
                }
            ],
        },
        "tags": [{"key": "environment", "value": "dev"}],
    }

    class _Ctx:
        region = "us-east-1"
        scope = type("S", (), {"scope_id": "aws:1"})()

    art = _codebuild_artifact(_Ctx(), project)  # type: ignore[arg-type]
    assert art is not None
    assert art.properties["environment"] == "dev"
    rels = {(e.rel_type, e.target_native_id.split(":")[0]) for e in art.edges}
    assert ("WRITES", "S3Bucket") in rels
    assert ("READS", "S3Bucket") in rels
    assert ("EXECUTES_AS", "arn") in {(e.rel_type, e.target_native_id[:3]) for e in art.edges} or any(
        e.rel_type == "EXECUTES_AS" for e in art.edges
    )
    assert any(e.rel_type == "READS" and "Secret:" in e.target_native_id for e in art.edges)


def test_codepipeline_artifact_store_and_env_tag():
    pipeline = {
        "name": "corp-prod",
        "roleArn": "arn:aws:iam::1:role/prod-cicd",
        "artifactStore": {"type": "S3", "location": "shared-artifacts"},
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "Src",
                        "actionTypeId": {
                            "category": "Source",
                            "owner": "AWS",
                            "provider": "S3",
                            "version": "1",
                        },
                        "configuration": {"S3Bucket": "shared-artifacts", "S3ObjectKey": "app.zip"},
                    }
                ],
            }
        ],
    }
    class _Ctx:
        region = "us-east-1"
        scope = type("S", (), {"scope_id": "aws:1"})()

    art = _codepipeline_artifact(
        _Ctx(),  # type: ignore[arg-type]
        pipeline,
        meta={"pipelineArn": "arn:aws:codepipeline:us-east-1:1:corp-prod"},
        tag_list=[{"key": "Environment", "value": "production"}],
    )
    assert art.properties["environment"] == "prod"
    assert any(e.rel_type == "WRITES" and e.target_native_id == "S3Bucket:shared-artifacts" for e in art.edges)


def test_cicd_feeds_prod_consumer():
    builder = GraphBuilder("cicd-feeds")
    build = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="CodeBuildProject:build",
        props={"resource_type": "CodeBuildProject", "environment": "dev", "name": "build"},
    )
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="S3Bucket:shared-artifacts",
        props={"resource_type": "S3Bucket", "bucket_name": "shared-artifacts"},
    )
    prod = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:prod-app",
        props={"resource_type": "LambdaFunction", "environment": "prod", "name": "prod-app"},
    )
    builder.add_edge(
        src_id=build,
        rel_type="WRITES",
        dst_id=bucket,
        props={"resource": "shared-artifacts", "resource_type": "S3Bucket"},
    )
    builder.add_edge(
        src_id=prod,
        rel_type="READS",
        dst_id=bucket,
        props={"resource": "shared-artifacts", "resource_type": "S3Bucket"},
    )
    stats = enrich_resource_pivots(builder)
    assert stats["feeds_edges"] >= 1
    paths = find_attack_paths(builder.snapshot, start_node_id=build, end_node_id=prod, max_depth=3)
    assert paths
    assert any(s.rel_type == "FEEDS" for s in paths[0].steps)


def test_shared_across_envs_marks_bucket():
    builder = GraphBuilder("shared-env")
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="S3Bucket:corp-static",
        props={"resource_type": "S3Bucket", "bucket_name": "corp-static"},
    )
    for env, nid in (("dev", "site-dev"), ("prod", "site-prod")):
        site = builder.add_concept_node(
            concept_type=ConceptType.RUNTIME_BINDING,
            native_id=f"S3Website:{nid}",
            props={"resource_type": "S3Website", "environment": env, "consumer_kind": "static-site"},
        )
        builder.add_edge(
            src_id=site,
            rel_type="READS",
            dst_id=bucket,
            props={"resource": "corp-static", "resource_type": "S3Bucket"},
        )
    stats = enrich_shared_environments(builder)
    assert stats["shared_across_envs"] >= 1
    assert builder.snapshot.nodes[bucket].props.get("shared_across_envs") is True
    assert is_high_value(builder.snapshot.nodes[bucket].props)
    consumers = list_resource_consumers(builder.snapshot, bucket)
    assert len(consumers["consumers"]) == 2
    assert set(consumers["environments"]) == {"dev", "prod"}


def test_canonicalize_env_aliases():
    assert canonicalize_environment("Production") == "prod"
    assert environment_from_tags({"Environment": "staging"}) == "staging"


def test_cloudfront_origin_bucket_parse():
    assert _bucket_from_origin_domain("corp-static.s3.us-east-1.amazonaws.com") == "corp-static"
    assert _bucket_from_origin_domain("corp-static.s3-website-us-east-1.amazonaws.com") == "corp-static"


def test_mechanism_marking_and_ssrf_hypothesis():
    props: dict = {"ssrf_vulnerable": True}
    assert _is_ssrf_hypothesis(props)
    apply_marking(props, compromised=True, mechanism="ssrf", source="test")
    assert props[COMPROMISE_MECHANISM] == "ssrf"
    assert props["is_compromised"] is True

    builder = GraphBuilder("mech-ssrf")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/ssrf-exec",
        props={"native_kind": "Role", "arn": "arn:aws:iam::1:role/ssrf-exec"},
    )
    fn = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:ssrf",
        props={
            "resource_type": "LambdaFunction",
            "function_name": "ssrf",
            COMPROMISE_MECHANISM: "ssrf",
            "execution_role_arn": "arn:aws:iam::1:role/ssrf-exec",
        },
    )
    builder.add_edge(src_id=fn, rel_type="EXECUTES_AS", dst_id=role, props={"role_arn": "arn:aws:iam::1:role/ssrf-exec"})
    stats = enrich_attack_surface(builder, provider=CloudProvider.AWS)
    assert stats["ssrf_chains"] >= 1
