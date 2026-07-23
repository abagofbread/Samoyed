"""Static hosting / CDN consumers of S3 — browser-facing poison targets.

CloudFront origins and S3 website endpoints READ/PULL the bucket so WRITES∩FEEDS
illustrates content-injection / stored-XSS geometry without an xss_vulnerable flag.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.aws.tags import environment_from_tags, normalize_tag_map
from samoyed.enumerators.contracts import ConceptEnumerator
from samoyed.enumerators.runner import paginate_call

_S3_WEBSITE = re.compile(
    r"^([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com$",
    re.I,
)
_S3_REST = re.compile(
    r"^([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-]([a-z0-9-]+)\.amazonaws\.com$",
    re.I,
)
_S3_PATH = re.compile(r"^s3\.([a-z0-9-]+)\.amazonaws\.com/([^/]+)", re.I)


class AwsStaticHostingEnumerator:
    concept = ConceptType.RUNTIME_BINDING
    name = "aws-static-hosting"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        yield from enumerate_s3_websites(ctx)
        yield from enumerate_cloudfront_distributions(ctx)


def enumerate_s3_websites(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    """Attach website consumer stubs for buckets that have website hosting enabled."""
    cred = ctx.credentials
    s3 = cred.client("s3")  # type: ignore[attr-defined]
    listed = paginate_call(ctx, operation="s3:ListBuckets", call=lambda: s3.list_buckets())
    if not listed:
        return
    for bucket in listed.get("Buckets") or []:
        name = bucket.get("Name")
        if not name:
            continue
        website = paginate_call(
            ctx,
            operation="s3:GetBucketWebsite",
            call=lambda n=name: s3.get_bucket_website(Bucket=n),
        )
        if not website:
            continue
        tags_resp = paginate_call(
            ctx,
            operation="s3:GetBucketTagging",
            call=lambda n=name: s3.get_bucket_tagging(Bucket=n),
        )
        tags = normalize_tag_map((tags_resp or {}).get("TagSet"))
        env = environment_from_tags(tags)
        consumer_id = f"S3Website:{name}"
        bucket_id = f"S3Bucket:{name}"
        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id=consumer_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "resource_type": "S3Website",
                "native_kind": "S3Website",
                "bucket_name": name,
                "consumer_kind": "static-site",
                "tags": tags,
                "environment": env,
                "display_name": f"S3 website {name}" + (f" ({env})" if env else ""),
                "index_document": ((website.get("IndexDocument") or {}).get("Suffix")),
            },
            evidence=Evidence("s3:GetBucketWebsite", {"bucket": name}),
            edges=[
                ConceptEdge(
                    rel_type="READS",
                    target_native_id=bucket_id,
                    target_concept_type=ConceptType.DATA_STORE,
                    props={
                        "resource": name,
                        "resource_type": "S3Bucket",
                        "source": "s3-website",
                        "discovered_via": "config",
                        "consumer_kind": "static-site",
                    },
                    confidence=ConfidenceType.EXPLICIT,
                )
            ],
        )
        # Ensure bucket node carries tags/env for shared-env enrichment
        yield ConceptArtifact(
            concept_type=ConceptType.DATA_STORE,
            provider=CloudProvider.AWS,
            native_id=bucket_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "resource_type": "S3Bucket",
                "bucket_name": name,
                "tags": tags,
                "environment": env,
                "has_website": True,
            },
            evidence=Evidence("s3:GetBucketWebsite", {"bucket": name, "tags": bool(tags)}),
        )


def enumerate_cloudfront_distributions(ctx: EnumContext) -> Iterator[ConceptArtifact]:
    cred = ctx.credentials
    cf = cred.client("cloudfront")  # type: ignore[attr-defined]
    listed = paginate_call(
        ctx,
        operation="cloudfront:ListDistributions",
        call=lambda: cf.list_distributions(),
    )
    if not listed:
        return
    dist_list = ((listed.get("DistributionList") or {}).get("Items")) or []
    for dist in dist_list:
        dist_id = dist.get("Id")
        arn = dist.get("ARN") or f"arn:aws:cloudfront::{_guess_account(ctx)}:distribution/{dist_id}"
        domain = dist.get("DomainName")
        aliases = (dist.get("Aliases") or {}).get("Items") or []
        origins = ((dist.get("Origins") or {}).get("Items")) or []
        edges: list[ConceptEdge] = []
        origin_buckets: list[str] = []
        for origin in origins:
            domain_name = origin.get("DomainName") or ""
            bucket = _bucket_from_origin_domain(domain_name)
            oai = origin.get("OriginPath")
            if bucket:
                origin_buckets.append(bucket)
                edges.append(
                    ConceptEdge(
                        rel_type="READS",
                        target_native_id=f"S3Bucket:{bucket}",
                        target_concept_type=ConceptType.DATA_STORE,
                        props={
                            "resource": bucket,
                            "resource_type": "S3Bucket",
                            "source": "cloudfront-origin",
                            "discovered_via": "config",
                            "consumer_kind": "cdn",
                            "origin_id": origin.get("Id"),
                            "origin_path": oai,
                        },
                        confidence=ConfidenceType.EXPLICIT,
                    )
                )
            # Also parse s3:// style CustomOrigin? usually DomainName only

        tags_resp = paginate_call(
            ctx,
            operation="cloudfront:ListTagsForResource",
            call=lambda a=arn: cf.list_tags_for_resource(Resource=a),
        )
        tag_items = ((tags_resp or {}).get("Tags") or {}).get("Items") or []
        tags = normalize_tag_map(tag_items)
        env = environment_from_tags(tags)

        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id=f"CloudFrontDistribution:{arn}",
            scope_id=ctx.scope.scope_id,
            properties={
                "resource_type": "CloudFrontDistribution",
                "native_kind": "CloudFrontDistribution",
                "distribution_id": dist_id,
                "arn": arn,
                "domain_name": domain,
                "aliases": aliases,
                "origin_buckets": origin_buckets,
                "consumer_kind": "cdn",
                "tags": tags,
                "environment": env,
                "display_name": f"CloudFront {dist_id}" + (f" ({env})" if env else ""),
            },
            evidence=Evidence("cloudfront:ListDistributions", {"id": dist_id}),
            edges=edges,
        )


def _bucket_from_origin_domain(domain: str) -> str | None:
    domain = (domain or "").strip().rstrip(".")
    if not domain:
        return None
    for pattern in (_S3_WEBSITE, _S3_REST):
        m = pattern.match(domain)
        if m:
            return m.group(1)
    m = _S3_PATH.match(domain)
    if m:
        return m.group(2)
    # bare bucket.s3.amazonaws.com
    if ".s3.amazonaws.com" in domain.lower():
        return domain.split(".s3", 1)[0]
    return None


def _guess_account(ctx: EnumContext) -> str:
    sid = ctx.scope.scope_id or ""
    for part in sid.split(":"):
        if part.isdigit() and len(part) == 12:
            return part
    return "000000000000"
