from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.credentials.k8s import pod_native_id, sa_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.k8s.helpers import call_k8s


class K8sWorkloadEnumerator:
    concept = ConceptType.WORKLOAD
    name = "k8s-workloads"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        core = cred.client("core")  # type: ignore[attr-defined]
        ns_list = call_k8s(ctx, operation="core/v1:namespaces", call=lambda: core.list_namespace())
        namespaces = [ns.metadata.name for ns in ns_list.items] if ns_list else ["default"]

        for namespace in namespaces:
            pods = call_k8s(
                ctx,
                operation=f"core/v1:pods:{namespace}",
                call=lambda ns=namespace: core.list_namespaced_pod(namespace=ns),
            )
            if not pods:
                continue
            for pod in pods.items:
                name = pod.metadata.name
                native_id = pod_native_id(namespace, name)
                sa_name = pod.spec.service_account_name or "default"
                sa_id = sa_native_id(namespace, sa_name)
                images = _container_images(pod)

                edges = [
                    ConceptEdge(
                        rel_type="EXECUTES_AS",
                        target_native_id=sa_id,
                        target_concept_type=ConceptType.IDENTITY,
                        props={"service_account": sa_name},
                    )
                ]
                for image in images:
                    image_id = f"kubernetes:image:{image}"
                    edges.append(
                        ConceptEdge(
                            rel_type="USES_IMAGE",
                            target_native_id=image_id,
                            target_concept_type=ConceptType.IMAGE_PROVENANCE,
                            props={"image": image},
                        )
                    )

                yield ConceptArtifact(
                    concept_type=ConceptType.WORKLOAD,
                    provider=CloudProvider.KUBERNETES,
                    native_id=native_id,
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "native_kind": "Pod",
                        "namespace": namespace,
                        "name": name,
                        "service_account": sa_name,
                        "images": images,
                        "display_name": f"{namespace}/{name}",
                    },
                    evidence=Evidence("core/v1:pods", {"namespace": namespace, "name": name}),
                    edges=edges,
                )


def _container_images(pod) -> list[str]:
    images: list[str] = []
    spec = pod.spec
    for container in (spec.containers or []) + (spec.init_containers or []):
        if container.image:
            images.append(container.image)
    return images


def pod_spec_dict(pod) -> dict[str, Any]:
    """Convert pod object to a plain dict for escape analysis."""
    data: dict[str, Any] = {
        "metadata": {"namespace": pod.metadata.namespace, "name": pod.metadata.name},
        "spec": {},
    }
    spec = pod.spec
    if spec.service_account_name:
        data["spec"]["serviceAccountName"] = spec.service_account_name
    if spec.host_pid:
        data["spec"]["hostPID"] = spec.host_pid
    if spec.host_network:
        data["spec"]["hostNetwork"] = spec.host_network
    containers = []
    for c in (spec.containers or []) + (spec.init_containers or []):
        entry: dict[str, Any] = {"name": c.name, "image": c.image}
        if c.security_context:
            sc = c.security_context
            entry["securityContext"] = {
                "privileged": sc.privileged,
                "allowPrivilegeEscalation": sc.allow_privilege_escalation,
                "runAsUser": sc.run_as_user,
                "capabilities": (
                    {"add": list(sc.capabilities.add or [])} if sc.capabilities else None
                ),
            }
        if c.volume_mounts:
            entry["volumeMounts"] = [{"mountPath": vm.mount_path, "name": vm.name} for vm in c.volume_mounts]
        containers.append(entry)
    data["spec"]["containers"] = containers
    if spec.volumes:
        vols = []
        for v in spec.volumes:
            vol: dict[str, Any] = {"name": v.name}
            if v.host_path:
                vol["hostPath"] = {"path": v.host_path.path}
            vols.append(vol)
        data["spec"]["volumes"] = vols
    return data
