from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.k8s.helpers import call_k8s


class K8sSecretEnumerator:
    concept = ConceptType.SECRET_STORE
    name = "k8s-secrets"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        core = cred.client("core")  # type: ignore[attr-defined]
        ns_list = call_k8s(ctx, operation="core/v1:namespaces", call=lambda: core.list_namespace())
        namespaces = [ns.metadata.name for ns in ns_list.items] if ns_list else ["default"]

        for namespace in namespaces:
            secrets = call_k8s(
                ctx,
                operation=f"core/v1:secrets:{namespace}",
                call=lambda ns=namespace: core.list_namespaced_secret(namespace=ns),
            )
            if not secrets:
                continue
            for secret in secrets.items:
                name = secret.metadata.name
                native_id = f"kubernetes:secret:{namespace}:{name}"
                yield ConceptArtifact(
                    concept_type=ConceptType.SECRET_STORE,
                    provider=CloudProvider.KUBERNETES,
                    native_id=native_id,
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "resource_type": "KubernetesSecret",
                        "namespace": namespace,
                        "name": name,
                        "display_name": f"Secret {namespace}/{name}",
                        "secret_type": secret.type,
                    },
                    evidence=Evidence("core/v1:secrets", {"namespace": namespace, "name": name}),
                )
