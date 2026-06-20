from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.k8s import cluster_api_native_id, namespace_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.k8s.helpers import call_k8s


class K8sScopeEnumerator:
    concept = ConceptType.ORCHESTRATION_SCOPE
    name = "k8s-scope"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        cluster = ctx.scope.properties.get("cluster", "cluster")
        cluster_id = ctx.scope.scope_id

        yield ConceptArtifact(
            concept_type=ConceptType.ORCHESTRATION_SCOPE,
            provider=CloudProvider.KUBERNETES,
            native_id=cluster_id,
            scope_id=cluster_id,
            properties={
                "native_kind": "Cluster",
                "cluster": cluster,
                "display_name": ctx.scope.display_name,
            },
            evidence=Evidence("kubeconfig:cluster", {"cluster": cluster}),
        )

        yield ConceptArtifact(
            concept_type=ConceptType.MANAGEMENT_ENDPOINT,
            provider=CloudProvider.KUBERNETES,
            native_id=cluster_api_native_id(cluster),
            scope_id=cluster_id,
            properties={
                "resource_type": "KubernetesAPI",
                "cluster": cluster,
                "display_name": f"Kubernetes API ({cluster})",
            },
            evidence=Evidence("kubeconfig:api-server", {"cluster": cluster}),
        )

        core = cred.client("core")  # type: ignore[attr-defined]
        ns_list = call_k8s(ctx, operation="core/v1:namespaces", call=lambda: core.list_namespace())
        if not ns_list:
            return
        for ns in ns_list.items:
            name = ns.metadata.name
            yield ConceptArtifact(
                concept_type=ConceptType.ORCHESTRATION_SCOPE,
                provider=CloudProvider.KUBERNETES,
                native_id=namespace_native_id(name),
                scope_id=cluster_id,
                properties={
                    "native_kind": "Namespace",
                    "namespace": name,
                    "display_name": f"Namespace {name}",
                },
                evidence=Evidence("core/v1:namespaces", {"namespace": name}),
            )
