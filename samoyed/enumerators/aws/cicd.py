"""AWS CI/CD substrate — CodeBuild + CodePipeline.

Emits RuntimeBindings that EXECUTES_AS service roles, READS secrets/source from
config, and WRITES artifact S3 (so FEEDS can poison prod consumers).
"""

from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.aws.config_refs import config_reads_edges
from samoyed.enumerators.aws.runtime_bindings import executes_as_edge
from samoyed.enumerators.aws.tags import environment_from_tags, normalize_tag_map
from samoyed.enumerators.contracts import ConceptEnumerator
from samoyed.enumerators.runner import paginate_call


class AwsCicdEnumerator:
    concept = ConceptType.RUNTIME_BINDING
    name = "aws-cicd"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        yield from enumerate_codebuild_projects(ctx)
        yield from enumerate_codepipelines(ctx)


def enumerate_codebuild_projects(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    cb = cred.client("codebuild")  # type: ignore[attr-defined]
    listed = paginate_call(ctx, operation="codebuild:ListProjects", call=lambda: cb.list_projects())
    if not listed:
        return
    names = list(listed.get("projects") or [])
    next_token = listed.get("nextToken")
    while next_token:
        more = paginate_call(
            ctx,
            operation="codebuild:ListProjects",
            call=lambda t=next_token: cb.list_projects(nextToken=t),
        )
        if not more:
            break
        names.extend(more.get("projects") or [])
        next_token = more.get("nextToken")

    for i in range(0, len(names), 100):
        batch = names[i : i + 100]
        detail = paginate_call(
            ctx,
            operation="codebuild:BatchGetProjects",
            call=lambda b=batch: cb.batch_get_projects(names=b),
        )
        if not detail:
            continue
        for project in detail.get("projects") or []:
            art = _codebuild_artifact(ctx, project)
            if art:
                yield art


def _codebuild_artifact(ctx: EnumContext, project: dict[str, Any]) -> ConceptArtifact | None:
    name = project.get("name")
    arn = project.get("arn") or f"arn:aws:codebuild:{ctx.region}:{_guess_account(ctx)}:project/{name}"
    if not name:
        return None
    role = project.get("serviceRole")
    tags = normalize_tag_map(project.get("tags"))
    env_tag = environment_from_tags(tags)

    edges: list[ConceptEdge] = []
    if role:
        edges.append(executes_as_edge(role, resource_type="CodeBuildProject", project=name))

    env_map: dict[str, str] = {}
    env_cfg = project.get("environment") or {}
    for var in env_cfg.get("environmentVariables") or []:
        vname = var.get("name") or ""
        val = var.get("value") or ""
        vtype = (var.get("type") or "PLAINTEXT").upper()
        if not vname:
            continue
        if vtype == "SECRETS_MANAGER" and val:
            env_map[vname] = val if val.startswith("arn:") else f"arn:aws:secretsmanager:{ctx.region}:_:secret:{val}"
        elif vtype == "PARAMETER_STORE" and val:
            path = val if val.startswith("/") else f"/{val}"
            env_map[vname] = f"arn:aws:ssm:{ctx.region}:_:parameter{path}"
        elif val:
            env_map[vname] = val

    edges.extend(config_reads_edges(source="codebuild-config", env=env_map or None))

    image = env_cfg.get("image")
    if image and "/" in str(image) and "amazonaws.com" in str(image):
        edges.extend(config_reads_edges(source="codebuild-config", image_uri=str(image)))

    artifacts = project.get("artifacts") or {}
    edges.extend(_s3_write_edges(artifacts, source="codebuild-artifacts"))
    for secondary in project.get("secondaryArtifacts") or []:
        edges.extend(_s3_write_edges(secondary, source="codebuild-secondary-artifacts"))

    source = project.get("source") or {}
    edges.extend(_s3_read_edges_from_source(source, source_label="codebuild-source"))

    native_id = f"CodeBuildProject:{arn}"
    return ConceptArtifact(
        concept_type=ConceptType.RUNTIME_BINDING,
        provider=CloudProvider.AWS,
        native_id=native_id,
        scope_id=ctx.scope.scope_id,
        properties={
            "resource_type": "CodeBuildProject",
            "native_kind": "CodeBuildProject",
            "name": name,
            "arn": arn,
            "execution_role_arn": role,
            "tags": tags,
            "environment": env_tag,
            "display_name": f"CodeBuild {name}" + (f" ({env_tag})" if env_tag else ""),
        },
        evidence=Evidence("codebuild:BatchGetProjects", {"name": name, "arn": arn}),
        edges=edges,
    )


def enumerate_codepipelines(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    cp = cred.client("codepipeline")  # type: ignore[attr-defined]
    listed = paginate_call(ctx, operation="codepipeline:ListPipelines", call=lambda: cp.list_pipelines())
    if not listed:
        return
    summaries = list(listed.get("pipelines") or [])
    next_token = listed.get("nextToken")
    while next_token:
        more = paginate_call(
            ctx,
            operation="codepipeline:ListPipelines",
            call=lambda t=next_token: cp.list_pipelines(nextToken=t),
        )
        if not more:
            break
        summaries.extend(more.get("pipelines") or [])
        next_token = more.get("nextToken")

    for summary in summaries:
        pname = summary.get("name")
        if not pname:
            continue
        detail = paginate_call(
            ctx,
            operation="codepipeline:GetPipeline",
            call=lambda n=pname: cp.get_pipeline(name=n),
        )
        if not detail:
            continue
        pipeline = detail.get("pipeline") or {}
        meta = detail.get("metadata") or {}
        tags_resp = paginate_call(
            ctx,
            operation="codepipeline:ListTagsForResource",
            call=lambda a=meta.get("pipelineArn"): cp.list_tags_for_resource(resourceArn=a) if a else None,
        )
        tag_list = (tags_resp or {}).get("tags") or pipeline.get("tags") or []
        yield _codepipeline_artifact(ctx, pipeline, meta=meta, tag_list=tag_list)


def _codepipeline_artifact(
    ctx: EnumContext,
    pipeline: dict[str, Any],
    *,
    meta: dict[str, Any],
    tag_list: list[Any],
) -> ConceptArtifact:
    name = pipeline.get("name") or "pipeline"
    arn = meta.get("pipelineArn") or f"arn:aws:codepipeline:{ctx.region}:{_guess_account(ctx)}:{name}"
    role = pipeline.get("roleArn")
    tags = normalize_tag_map(tag_list)
    env_tag = environment_from_tags(tags)

    edges: list[ConceptEdge] = []
    if role:
        edges.append(executes_as_edge(role, resource_type="CodePipeline", pipeline=name))

    store = pipeline.get("artifactStore") or {}
    if store.get("type") == "S3" and store.get("location"):
        edges.append(_writes_s3_edge(store["location"], source="codepipeline-artifact-store"))
    for _region, store in (pipeline.get("artifactStores") or {}).items():
        if isinstance(store, dict) and store.get("location"):
            edges.append(_writes_s3_edge(store["location"], source="codepipeline-artifact-store"))

    blobs: list[Any] = []
    for stage in pipeline.get("stages") or []:
        for action in stage.get("actions") or []:
            cfg = action.get("configuration") or {}
            blobs.append(cfg)
            bucket = cfg.get("S3Bucket") or cfg.get("BucketName")
            if bucket:
                provider = ((action.get("actionTypeId") or {}).get("provider") or "").lower()
                category = ((action.get("actionTypeId") or {}).get("category") or "").lower()
                if category == "source" or (provider == "s3" and category != "deploy"):
                    edges.append(
                        ConceptEdge(
                            rel_type="READS",
                            target_native_id=f"S3Bucket:{bucket}",
                            target_concept_type=ConceptType.DATA_STORE,
                            props={
                                "resource": bucket,
                                "resource_type": "S3Bucket",
                                "source": "codepipeline-action",
                                "discovered_via": "config",
                                "action": action.get("name"),
                            },
                        )
                    )
                else:
                    edges.append(_writes_s3_edge(bucket, source="codepipeline-action"))
            ecr = cfg.get("RepositoryName")
            if ecr and ((action.get("actionTypeId") or {}).get("provider") or "").lower() == "ecr":
                edges.append(
                    ConceptEdge(
                        rel_type="READS",
                        target_native_id=f"ECRRepository:{ecr}",
                        target_concept_type=ConceptType.REGISTRY_STORE,
                        props={
                            "resource": ecr,
                            "resource_type": "ECRRepository",
                            "source": "codepipeline-action",
                            "discovered_via": "config",
                        },
                    )
                )

    edges.extend(config_reads_edges(source="codepipeline-config", extra_blobs=blobs))

    return ConceptArtifact(
        concept_type=ConceptType.RUNTIME_BINDING,
        provider=CloudProvider.AWS,
        native_id=f"CodePipeline:{arn}",
        scope_id=ctx.scope.scope_id,
        properties={
            "resource_type": "CodePipeline",
            "native_kind": "CodePipeline",
            "name": name,
            "arn": arn,
            "execution_role_arn": role,
            "tags": tags,
            "environment": env_tag,
            "display_name": f"Pipeline {name}" + (f" ({env_tag})" if env_tag else ""),
        },
        evidence=Evidence("codepipeline:GetPipeline", {"name": name, "arn": arn}),
        edges=edges,
    )


def _s3_write_edges(artifacts: dict[str, Any], *, source: str) -> list[ConceptEdge]:
    if (artifacts.get("type") or "").upper() != "S3":
        return []
    location = artifacts.get("location") or ""
    if not location:
        return []
    bucket = location.split("/", 1)[0]
    return [_writes_s3_edge(bucket, source=source, prefix=location if "/" in location else None)]


def _s3_read_edges_from_source(source: dict[str, Any], *, source_label: str) -> list[ConceptEdge]:
    if (source.get("type") or "").upper() != "S3":
        return []
    location = source.get("location") or ""
    if not location:
        return []
    bucket = location.split("/", 1)[0]
    return [
        ConceptEdge(
            rel_type="READS",
            target_native_id=f"S3Bucket:{bucket}",
            target_concept_type=ConceptType.DATA_STORE,
            props={
                "resource": bucket,
                "resource_type": "S3Bucket",
                "source": source_label,
                "discovered_via": "config",
            },
            confidence=ConfidenceType.EXPLICIT,
        )
    ]


def _writes_s3_edge(bucket: str, *, source: str, prefix: str | None = None) -> ConceptEdge:
    bucket = bucket.split("/", 1)[0]
    props: dict[str, Any] = {
        "resource": bucket,
        "resource_type": "S3Bucket",
        "source": source,
        "discovered_via": "config",
    }
    if prefix:
        props["resource"] = prefix
    return ConceptEdge(
        rel_type="WRITES",
        target_native_id=f"S3Bucket:{bucket}",
        target_concept_type=ConceptType.DATA_STORE,
        props=props,
        confidence=ConfidenceType.EXPLICIT,
    )


def _guess_account(ctx: EnumContext) -> str:
    sid = ctx.scope.scope_id or ""
    for part in sid.split(":"):
        if part.isdigit() and len(part) == 12:
            return part
    return "000000000000"
