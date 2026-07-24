from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.k8s import sa_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.k8s.helpers import call_k8s

IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
GKE_ANNOTATION = "iam.gke.io/gcp-service-account"
AKS_CLIENT_ANNOTATION = "azure.workload.identity/client-id"
AKS_TENANT_ANNOTATION = "azure.workload.identity/tenant-id"


class K8sCloudBindingEnumerator:
    concept = ConceptType.RUNTIME_BINDING
    name = "k8s-cloud-binding"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        core = cred.client("core")  # type: ignore[attr-defined]
        ns_list = call_k8s(ctx, operation="core/v1:namespaces", call=lambda: core.list_namespace())
        namespaces = [ns.metadata.name for ns in ns_list.items] if ns_list else ["default"]

        for namespace in namespaces:
            resp = call_k8s(
                ctx,
                operation=f"core/v1:serviceaccounts:{namespace}",
                call=lambda ns=namespace: core.list_namespaced_service_account(namespace=ns),
            )
            if not resp:
                continue
            for sa in resp.items:
                annotations = sa.metadata.annotations or {}
                sa_id = sa_native_id(namespace, sa.metadata.name)
                edges: list[ConceptEdge] = []

                if role_arn := annotations.get(IRSA_ANNOTATION):
                    edges.append(
                        ConceptEdge(
                            rel_type="PROJECTS_TO",
                            src_native_id=sa_id,
                            target_native_id=role_arn,
                            target_concept_type=ConceptType.IDENTITY,
                            props={"binding_type": "IRSA", "annotation": IRSA_ANNOTATION},
                            confidence=ConfidenceType.EXPLICIT,
                        )
                    )
                    yield ConceptArtifact(
                        concept_type=ConceptType.RUNTIME_BINDING,
                        provider=CloudProvider.KUBERNETES,
                        native_id=f"kubernetes:irsa:{namespace}:{sa.metadata.name}",
                        scope_id=ctx.scope.scope_id,
                        properties={
                            "native_kind": "IRSA",
                            "namespace": namespace,
                            "service_account": sa.metadata.name,
                            "cloud_role_arn": role_arn,
                            "provider_hint": "aws",
                        },
                        evidence=Evidence("core/v1:serviceaccounts:annotation", {"annotation": IRSA_ANNOTATION}),
                        edges=edges,
                    )
                    edges = []

                if gcp_sa := annotations.get(GKE_ANNOTATION):
                    target = f"gcp:serviceaccount:{gcp_sa}"
                    yield ConceptArtifact(
                        concept_type=ConceptType.IDENTITY,
                        provider=CloudProvider.GCP,
                        native_id=target,
                        scope_id=ctx.scope.scope_id,
                        properties={
                            "native_kind": "ServiceAccount",
                            "email": gcp_sa,
                            "display_name": gcp_sa,
                            "projected": True,
                            "projected_reason": "gke-workload-identity",
                        },
                        evidence=Evidence("core/v1:serviceaccounts:annotation", {"annotation": GKE_ANNOTATION}),
                    )
                    edges.append(
                        ConceptEdge(
                            rel_type="PROJECTS_TO",
                            src_native_id=sa_id,
                            target_native_id=target,
                            target_concept_type=ConceptType.IDENTITY,
                            props={
                                "binding_type": "WorkloadIdentity",
                                "annotation": GKE_ANNOTATION,
                                "trust_validated": False,
                                "mechanism": "wif",
                            },
                        )
                    )
                    yield ConceptArtifact(
                        concept_type=ConceptType.RUNTIME_BINDING,
                        provider=CloudProvider.KUBERNETES,
                        native_id=f"kubernetes:wi:{namespace}:{sa.metadata.name}",
                        scope_id=ctx.scope.scope_id,
                        properties={
                            "native_kind": "WorkloadIdentity",
                            "gcp_service_account": gcp_sa,
                            "provider_hint": "gcp",
                        },
                        evidence=Evidence("core/v1:serviceaccounts:annotation", {"annotation": GKE_ANNOTATION}),
                        edges=edges,
                    )
                    edges = []

                if annotations.get(AKS_CLIENT_ANNOTATION):
                    client_id = annotations.get(AKS_CLIENT_ANNOTATION)
                    tenant = annotations.get(AKS_TENANT_ANNOTATION, "")
                    target = f"azure:managedidentity:{client_id}"
                    edges.append(
                        ConceptEdge(
                            rel_type="PROJECTS_TO",
                            src_native_id=sa_id,
                            target_native_id=target,
                            target_concept_type=ConceptType.IDENTITY,
                            props={"binding_type": "AKSWorkloadIdentity", "tenant": tenant},
                        )
                    )
                    yield ConceptArtifact(
                        concept_type=ConceptType.RUNTIME_BINDING,
                        provider=CloudProvider.KUBERNETES,
                        native_id=f"kubernetes:aks-wi:{namespace}:{sa.metadata.name}",
                        scope_id=ctx.scope.scope_id,
                        properties={
                            "native_kind": "AKSWorkloadIdentity",
                            "client_id": client_id,
                            "tenant_id": tenant,
                            "provider_hint": "azure",
                        },
                        evidence=Evidence("core/v1:serviceaccounts:annotation", {"annotation": AKS_CLIENT_ANNOTATION}),
                        edges=edges,
                    )
