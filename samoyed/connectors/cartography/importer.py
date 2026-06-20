from __future__ import annotations

from typing import Any, Iterator

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.cloud.providers import make_scope_id
from samoyed.connectors.cartography.client import CartographyClient
from samoyed.connectors.cartography import queries as cq
from samoyed.credentials.gcp import sa_native_id
from samoyed.graph.builder import GraphBuilder
from samoyed.ingest.concept_normalizer import ConceptNormalizer


def import_cartography_graph(
    client: CartographyClient,
    *,
    session_id: str,
    caller_arn: str | None = None,
    account_id: str | None = None,
    project_id: str | None = None,
    provider: CloudProvider = CloudProvider.AWS,
) -> tuple[GraphBuilder, dict[str, Any]]:
    """Import a Cartography Neo4j graph into a Samoyed GraphBuilder."""
    artifacts = list(_collect_artifacts(client, account_id=account_id, project_id=project_id, caller_arn=caller_arn))
    if not artifacts:
        raise ValueError("No Cartography data found for the given filters")

    scope_id, scope_display = _resolve_scope(artifacts, account_id=account_id, project_id=project_id)
    builder = GraphBuilder(session_id)
    scope_node = builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id=scope_id,
        props={
            "display_name": scope_display,
            "source": "cartography",
            "account_id": account_id,
            "project_id": project_id,
        },
    )
    builder.link_session(scope_node)
    ConceptNormalizer().ingest(builder, artifacts)

    resolved_caller = caller_arn or _default_caller(artifacts)
    if resolved_caller:
        for node in builder.snapshot.nodes.values():
            if node.props.get("native_id") == resolved_caller or node.props.get("arn") == resolved_caller:
                node.props["is_caller"] = True

    attack_edges = apply_attack_analysis(builder, provider=provider)
    meta = {
        "source": "cartography",
        "artifact_count": len(artifacts),
        "node_count": len(builder.snapshot.nodes),
        "attack_patterns_matched": len(attack_edges),
        "cartography_account_id": account_id,
        "cartography_project_id": project_id,
        "caller_arn": resolved_caller,
    }
    return builder, meta


def _collect_artifacts(
    client: CartographyClient,
    *,
    account_id: str | None,
    project_id: str | None,
    caller_arn: str | None,
) -> Iterator[ConceptArtifact]:
    seen_accounts = set()
    for row in client.run(cq.AWS_ACCOUNTS, account_id=account_id):
        aid = row.get("account_id")
        if not aid or aid in seen_accounts:
            continue
        seen_accounts.add(aid)
        scope_id = make_scope_id(CloudProvider.AWS, "account", str(aid))
        yield ConceptArtifact(
            concept_type=ConceptType.SCOPE_BOUNDARY,
            provider=CloudProvider.AWS,
            native_id=scope_id,
            scope_id=scope_id,
            properties={"display_name": f"AWS account {aid}", "account_id": aid, "source": "cartography"},
            evidence=Evidence("cartography:AWSAccount", {"account_id": aid}),
        )

    for row in client.run(cq.AWS_PRINCIPALS, account_id=account_id):
        arn = row.get("arn")
        if not arn:
            continue
        labels = row.get("labels") or []
        kind = _aws_principal_kind(labels)
        scope_id = make_scope_id(CloudProvider.AWS, "account", str(row.get("account_id") or _account_from_arn(arn)))
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id=arn,
            scope_id=scope_id,
            properties={
                "native_kind": kind,
                "arn": arn,
                "name": row.get("name"),
                "display_name": row.get("name") or arn,
                "source": "cartography",
                "is_caller": caller_arn == arn,
            },
            evidence=Evidence("cartography:AWSPrincipal", {"arn": arn, "labels": labels}),
        )

    for row in client.run(cq.STS_ASSUME_ROLE_ALLOW, account_id=account_id):
        src, dst = row.get("src_arn"), row.get("dst_arn")
        if not src or not dst:
            continue
        scope_id = make_scope_id(CloudProvider.AWS, "account", _account_from_arn(dst))
        yield ConceptArtifact(
            concept_type=ConceptType.TRUST,
            provider=CloudProvider.AWS,
            native_id=f"cartography:trust:{src}->{dst}",
            scope_id=scope_id,
            properties={"source": "cartography", "relationship": "STS_ASSUMEROLE_ALLOW"},
            evidence=Evidence("cartography:STS_ASSUMEROLE_ALLOW", {"src": src, "dst": dst}),
            edges=[
                ConceptEdge(
                    rel_type="CAN_ASSUME_ROLE",
                    src_native_id=src,
                    target_native_id=dst,
                    target_concept_type=ConceptType.IDENTITY,
                    props={"source": "cartography"},
                    confidence=ConfidenceType.EXPLICIT,
                )
            ],
        )

    for row in client.run(cq.LAMBDA_ASSUMES_ROLE, account_id=account_id):
        lambda_arn = row.get("lambda_arn")
        role_arn = row.get("role_arn")
        if not lambda_arn or not role_arn:
            continue
        scope_id = make_scope_id(CloudProvider.AWS, "account", _account_from_arn(role_arn))
        native_id = f"LambdaFunction:{lambda_arn}"
        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id=native_id,
            scope_id=scope_id,
            properties={
                "resource_type": "LambdaFunction",
                "arn": lambda_arn,
                "function_name": row.get("name"),
                "execution_role_arn": role_arn,
                "source": "cartography",
            },
            evidence=Evidence("cartography:AWSLambda:ASSUMES", {"lambda": lambda_arn, "role": role_arn}),
            edges=[
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=role_arn,
                    target_concept_type=ConceptType.IDENTITY,
                    props={"source": "cartography"},
                )
            ],
        )

    for row in client.run(cq.EC2_INSTANCE_PROFILE_ROLE, account_id=account_id):
        role_arn = row.get("role_arn")
        iid = row.get("instance_id") or row.get("instance_arn")
        if not role_arn or not iid:
            continue
        scope_id = make_scope_id(CloudProvider.AWS, "account", _account_from_arn(role_arn))
        native_id = f"EC2Instance:{iid}"
        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.AWS,
            native_id=native_id,
            scope_id=scope_id,
            properties={
                "resource_type": "EC2Instance",
                "instance_id": iid,
                "instance_arn": row.get("instance_arn"),
                "execution_role_arn": role_arn,
                "source": "cartography",
            },
            evidence=Evidence("cartography:EC2Instance:INSTANCE_PROFILE", {"instance": iid, "role": role_arn}),
            edges=[
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=role_arn,
                    target_concept_type=ConceptType.IDENTITY,
                    props={"source": "cartography"},
                )
            ],
        )

    for row in client.run(cq.S3_ACCESS, account_id=account_id):
        src = row.get("src_arn")
        bucket_id = row.get("bucket_native_id")
        if not src or not bucket_id:
            continue
        rel = "READS" if row.get("access") == "CAN_READ" else "WRITES"
        scope_id = make_scope_id(CloudProvider.AWS, "account", _account_from_arn(src))
        bucket_native = f"S3Bucket:{row.get('bucket_name') or bucket_id}"
        yield ConceptArtifact(
            concept_type=ConceptType.DATA_STORE,
            provider=CloudProvider.AWS,
            native_id=bucket_native,
            scope_id=scope_id,
            properties={
                "resource_type": "S3Bucket",
                "bucket_name": row.get("bucket_name") or bucket_id,
                "source": "cartography",
            },
            evidence=Evidence(f"cartography:{row.get('access')}", {"bucket": bucket_native}),
            edges=[
                ConceptEdge(
                    rel_type=rel,
                    src_native_id=src,
                    target_native_id=bucket_native,
                    target_concept_type=ConceptType.DATA_STORE,
                    props={"source": "cartography", "cartography_rel": row.get("access")},
                    confidence=ConfidenceType.EXPLICIT,
                )
            ],
        )

    for row in client.run(cq.SECRETS_MANAGER, account_id=account_id):
        arn = row.get("arn")
        if not arn:
            continue
        scope_id = make_scope_id(CloudProvider.AWS, "account", str(row.get("account_id") or _account_from_arn(arn)))
        native_id = f"Secret:{arn}"
        yield ConceptArtifact(
            concept_type=ConceptType.SECRET_STORE,
            provider=CloudProvider.AWS,
            native_id=native_id,
            scope_id=scope_id,
            properties={
                "resource_type": "Secret",
                "arn": arn,
                "name": row.get("name"),
                "display_name": row.get("name") or arn,
                "source": "cartography",
                "content_hypothesis": "unknown",
            },
            evidence=Evidence("cartography:SecretsManagerSecret", {"arn": arn}),
        )

    for row in client.run(cq.DYNAMODB_ACCESS, account_id=account_id):
        src = row.get("src_arn")
        table_id = row.get("table_id")
        if not src or not table_id:
            continue
        scope_id = make_scope_id(CloudProvider.AWS, "account", _account_from_arn(src))
        native_id = f"DynamoDBTable:{table_id}"
        yield ConceptArtifact(
            concept_type=ConceptType.DATA_STORE,
            provider=CloudProvider.AWS,
            native_id=native_id,
            scope_id=scope_id,
            properties={"resource_type": "DynamoDBTable", "name": row.get("name") or table_id, "source": "cartography"},
            evidence=Evidence("cartography:CAN_QUERY", {"table": native_id}),
            edges=[
                ConceptEdge(
                    rel_type="READS",
                    src_native_id=src,
                    target_native_id=native_id,
                    target_concept_type=ConceptType.DATA_STORE,
                    props={"source": "cartography", "cartography_rel": "CAN_QUERY"},
                )
            ],
        )

    yield from _collect_gcp(client, project_id=project_id)
    yield from _collect_k8s(client)


def _collect_gcp(client: CartographyClient, *, project_id: str | None) -> Iterator[ConceptArtifact]:
    for row in client.run(cq.GCP_SERVICE_ACCOUNTS, project_id=project_id):
        email = row.get("email")
        if not email:
            continue
        pid = str(row.get("project_id") or "unknown")
        scope_id = make_scope_id(CloudProvider.GCP, "project", pid)
        native_id = sa_native_id(email)
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.GCP,
            native_id=native_id,
            scope_id=scope_id,
            properties={
                "native_kind": "ServiceAccount",
                "email": email,
                "display_name": email,
                "source": "cartography",
            },
            evidence=Evidence("cartography:GCPServiceAccount", {"email": email}),
        )


def _collect_k8s(client: CartographyClient) -> Iterator[ConceptArtifact]:
    clusters = {r.get("cluster_id"): r.get("name") for r in client.run(cq.K8S_CLUSTER)}
    for row in client.run(cq.K8S_SA):
        sa_id = row.get("sa_id")
        if not sa_id:
            continue
        cluster = row.get("cluster_id") or "cluster"
        scope_id = make_scope_id(CloudProvider.KUBERNETES, "cluster", str(cluster))
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.KUBERNETES,
            native_id=sa_id,
            scope_id=scope_id,
            properties={
                "native_kind": "ServiceAccount",
                "namespace": row.get("namespace"),
                "name": row.get("name"),
                "display_name": f"{row.get('namespace')}/{row.get('name')}",
                "cluster": clusters.get(cluster, cluster),
                "source": "cartography",
            },
            evidence=Evidence("cartography:KubernetesServiceAccount", {"id": sa_id}),
        )


def _aws_principal_kind(labels: list[Any]) -> str:
    label_set = {str(x) for x in labels}
    if "AWSRole" in label_set:
        return "Role"
    if "AWSUser" in label_set:
        return "User"
    if "AWSGroup" in label_set:
        return "Group"
    return "Principal"


def _account_from_arn(arn: str) -> str:
    parts = arn.split(":")
    if len(parts) >= 5 and parts[0] == "arn":
        return parts[4]
    return "unknown"


def _resolve_scope(
    artifacts: list[ConceptArtifact],
    *,
    account_id: str | None,
    project_id: str | None,
) -> tuple[str, str]:
    if account_id:
        sid = make_scope_id(CloudProvider.AWS, "account", account_id)
        return sid, f"AWS account {account_id} (Cartography)"
    if project_id:
        sid = make_scope_id(CloudProvider.GCP, "project", project_id)
        return sid, f"GCP project {project_id} (Cartography)"
    for art in artifacts:
        if art.concept_type == ConceptType.SCOPE_BOUNDARY:
            return art.native_id, art.properties.get("display_name", art.native_id)
    first = artifacts[0]
    return first.scope_id, "Cartography import scope"


def _default_caller(artifacts: list[ConceptArtifact]) -> str | None:
    for art in artifacts:
        if art.properties.get("is_caller"):
            return art.native_id
    for art in artifacts:
        if art.concept_type == ConceptType.IDENTITY and art.properties.get("native_kind") == "User":
            return art.native_id
    return None
