from __future__ import annotations

from typing import Any

from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot


def build_sample_k8s_graph(session_id: str = "sample-k8s") -> GraphSnapshot:
    """
    Offline vulnerable K8s graph for path testing without a live cluster.
    Paths:
      - app-sa READS db-credentials secret
      - app-sa CAN_ACCESS cluster API (secret-reader role also grants broad read)
      - evil-pod EXECUTES_AS app-sa, HAS_ESCAPE_SURFACE -> CAN_ESCAPE_TO node
      - irsa-sa PROJECTS_TO AWS admin role
    """
    builder = GraphBuilder(session_id)
    cluster = "samoyed-lab"

    app_sa = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="kubernetes:serviceaccount:default:app-sa",
        props={
            "native_kind": "ServiceAccount",
            "namespace": "default",
            "name": "app-sa",
            "is_caller": True,
            "display_name": "default/app-sa",
        },
    )
    irsa_sa = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="kubernetes:serviceaccount:default:irsa-sa",
        props={"native_kind": "ServiceAccount", "namespace": "default", "name": "irsa-sa"},
    )
    aws_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/eks-workload-admin",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/eks-workload-admin", "provider": "aws"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="kubernetes:secret:default:db-credentials",
        props={"resource_type": "KubernetesSecret", "namespace": "default", "name": "db-credentials"},
    )
    api = builder.add_concept_node(
        concept_type=ConceptType.MANAGEMENT_ENDPOINT,
        native_id=f"kubernetes:api:{cluster}",
        props={"resource_type": "KubernetesAPI", "cluster": cluster},
    )
    pod = builder.add_concept_node(
        concept_type=ConceptType.WORKLOAD,
        native_id="kubernetes:pod:default:evil-pod",
        props={"native_kind": "Pod", "namespace": "default", "name": "evil-pod", "service_account": "app-sa"},
    )
    escape = builder.add_concept_node(
        concept_type=ConceptType.ESCAPE_SURFACE,
        native_id="kubernetes:escape:default:evil-pod:docker-socket",
        props={"kind": "docker-socket", "severity": "critical", "description": "docker.sock mount"},
    )
    node_host = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id=f"kubernetes:node:host:{cluster}",
        props={"native_kind": "NodeHost", "cluster": cluster},
    )

    builder.add_edge(src_id=app_sa, rel_type="READS", dst_id=secret, props={"confidence": "explicit", "role": "secret-reader"})
    builder.add_edge(src_id=app_sa, rel_type="CAN_ACCESS", dst_id=api, props={"confidence": "explicit", "role": "secret-reader"})
    builder.add_edge(src_id=irsa_sa, rel_type="PROJECTS_TO", dst_id=aws_role, props={"binding_type": "IRSA"})
    builder.add_edge(src_id=pod, rel_type="EXECUTES_AS", dst_id=app_sa, props={"confidence": "explicit"})
    builder.add_edge(src_id=pod, rel_type="HAS_ESCAPE_SURFACE", dst_id=escape, props={"kind": "docker-socket"})
    builder.add_edge(src_id=escape, rel_type="CAN_ESCAPE_TO", dst_id=node_host, props={"severity": "critical"})

    for node_id in (app_sa, irsa_sa, aws_role, secret, api, pod, escape, node_host):
        builder.link_session(node_id)

    return builder.snapshot


def load_sample_k8s_session_metadata() -> dict[str, Any]:
    return {
        "caller_arn": "kubernetes:serviceaccount:default:app-sa",
        "scope_id": "kubernetes:cluster:samoyed-lab",
        "provider": "kubernetes",
        "artifact_count": 0,
        "node_count": 8,
        "sample": True,
        "platform": "kubernetes",
    }
