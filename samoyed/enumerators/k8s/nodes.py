"""K8s Node RuntimeBindings — escape landing zone + cloud instance linkage."""

from __future__ import annotations

import re
from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.k8s.helpers import call_k8s

# aws:///us-east-1a/i-0abc...  or  aws://us-east-1/i-0abc...
_AWS_PROVIDER = re.compile(r"aws:///(?:[^/]+)/+(i-[0-9a-f]+)", re.I)
_AWS_PROVIDER_ALT = re.compile(r"aws://[^/]*/(i-[0-9a-f]+)", re.I)
_GCP_PROVIDER = re.compile(r"gce://([^/]+)/([^/]+)/([^/]+)")
_AZURE_PROVIDER = re.compile(r"azure://(.+)$")


def node_native_id(cluster: str, node_name: str) -> str:
    return f"kubernetes:node:{cluster}:{node_name}"


def cluster_host_native_id(cluster: str) -> str:
    return f"kubernetes:node:host:{cluster}"


def parse_cloud_instance(provider_id: str | None) -> dict[str, str]:
    """Extract cloud instance identity from Node.spec.providerID."""
    if not provider_id:
        return {}
    m = _AWS_PROVIDER.search(provider_id) or _AWS_PROVIDER_ALT.search(provider_id)
    if m:
        iid = m.group(1)
        return {
            "cloud_provider": "aws",
            "aws_instance_id": iid,
            "ec2_native_id": f"EC2Instance:{iid}",
        }
    m = _GCP_PROVIDER.search(provider_id)
    if m:
        project, zone, name = m.group(1), m.group(2), m.group(3)
        return {
            "cloud_provider": "gcp",
            "gcp_project": project,
            "gcp_zone": zone,
            "gcp_instance": name,
            "gce_native_id": f"GCEInstance:{project}/{zone}/{name}",
        }
    m = _AZURE_PROVIDER.search(provider_id)
    if m:
        return {
            "cloud_provider": "azure",
            "azure_resource_id": m.group(1),
            "azure_vm_native_id": f"AzureVM:{m.group(1)}",
        }
    return {}


class K8sNodeEnumerator:
    concept = ConceptType.RUNTIME_BINDING
    name = "k8s-nodes"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        core = cred.client("core")  # type: ignore[attr-defined]
        cluster = ctx.scope.properties.get("cluster", "cluster")

        # Synthetic cluster-wide host (fallback when pod is unsched/unknown node)
        host_id = cluster_host_native_id(cluster)
        yield ConceptArtifact(
            concept_type=ConceptType.RUNTIME_BINDING,
            provider=CloudProvider.KUBERNETES,
            native_id=host_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": "NodeHost",
                "resource_type": "NodeHost",
                "cluster": cluster,
                "display_name": f"Node host ({cluster})",
            },
            evidence=Evidence("core/v1:nodes:synthetic-host", {"cluster": cluster}),
        )

        nodes = call_k8s(ctx, operation="core/v1:nodes", call=lambda: core.list_node())
        if not nodes:
            return

        for node in nodes.items:
            name = node.metadata.name
            provider_id = getattr(node.spec, "provider_id", None) or ""
            cloud = parse_cloud_instance(provider_id)
            nid = node_native_id(cluster, name)
            edges: list[ConceptEdge] = [
                ConceptEdge(
                    rel_type="HOSTED_IN",
                    target_native_id=host_id,
                    target_concept_type=ConceptType.RUNTIME_BINDING,
                    props={"cluster": cluster},
                )
            ]
            # Container escape to this node can steal the worker's cloud identity.
            if cloud.get("ec2_native_id"):
                edges.append(
                    ConceptEdge(
                        rel_type="CAN_ESCAPE_TO",
                        target_native_id=cloud["ec2_native_id"],
                        target_concept_type=ConceptType.RUNTIME_BINDING,
                        props={
                            "mechanism": "node-instance-profile",
                            "aws_instance_id": cloud["aws_instance_id"],
                            "discovered_via": "providerID",
                        },
                        confidence=ConfidenceType.EXPLICIT,
                    )
                )
                # Stub EC2 so the edge resolves in k8s-only sessions.
                yield ConceptArtifact(
                    concept_type=ConceptType.RUNTIME_BINDING,
                    provider=CloudProvider.AWS,
                    native_id=cloud["ec2_native_id"],
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "resource_type": "EC2Instance",
                        "instance_id": cloud["aws_instance_id"],
                        "discovered_via": "k8s-node-providerID",
                        "display_name": f"EC2 {cloud['aws_instance_id']} (EKS node)",
                    },
                    evidence=Evidence("core/v1:nodes:providerID", {"providerID": provider_id}),
                )
            elif cloud.get("gce_native_id"):
                edges.append(
                    ConceptEdge(
                        rel_type="CAN_ESCAPE_TO",
                        target_native_id=cloud["gce_native_id"],
                        target_concept_type=ConceptType.RUNTIME_BINDING,
                        props={"mechanism": "node-service-account", "discovered_via": "providerID"},
                    )
                )

            yield ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.KUBERNETES,
                native_id=nid,
                scope_id=ctx.scope.scope_id,
                properties={
                    "native_kind": "Node",
                    "resource_type": "KubernetesNode",
                    "cluster": cluster,
                    "name": name,
                    "provider_id": provider_id or None,
                    "display_name": f"Node {name}",
                    **cloud,
                },
                evidence=Evidence("core/v1:nodes", {"name": name, "providerID": provider_id}),
                edges=edges,
            )
