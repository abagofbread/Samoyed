from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.k8s import pod_native_id, sa_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.k8s.helpers import call_k8s
from samoyed.enumerators.k8s.nodes import cluster_host_native_id, node_native_id
from samoyed.enumerators.k8s.secret_consumers import image_pull_secret_names, secret_refs_from_pod_spec


class K8sWorkloadEnumerator:
    concept = ConceptType.WORKLOAD
    name = "k8s-workloads"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        core = cred.client("core")  # type: ignore[attr-defined]
        cluster = ctx.scope.properties.get("cluster", "cluster")
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
                spec = pod_spec_dict(pod)
                node_name = getattr(pod.spec, "node_name", None) or None

                edges = [
                    ConceptEdge(
                        rel_type="EXECUTES_AS",
                        target_native_id=sa_id,
                        target_concept_type=ConceptType.IDENTITY,
                        props={"service_account": sa_name},
                    )
                ]
                if node_name:
                    edges.append(
                        ConceptEdge(
                            rel_type="RUNS_ON",
                            target_native_id=node_native_id(cluster, node_name),
                            target_concept_type=ConceptType.RUNTIME_BINDING,
                            props={"node": node_name, "topology": True},
                        )
                    )

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

                for ref in secret_refs_from_pod_spec(spec):
                    secret_id = f"kubernetes:secret:{ref['namespace']}:{ref['name']}"
                    edges.append(
                        ConceptEdge(
                            rel_type="READS",
                            target_native_id=secret_id,
                            target_concept_type=ConceptType.SECRET_STORE,
                            props={
                                "resource_type": "KubernetesSecret",
                                "via": ref["via"],
                                "discovered_via": "pod-config",
                                "source": "k8s-pod-spec",
                            },
                            confidence=ConfidenceType.EXPLICIT,
                        )
                    )

                for pull_secret in image_pull_secret_names(spec):
                    secret_id = f"kubernetes:secret:{namespace}:{pull_secret}"
                    edges.append(
                        ConceptEdge(
                            rel_type="READS",
                            target_native_id=secret_id,
                            target_concept_type=ConceptType.SECRET_STORE,
                            props={
                                "resource_type": "KubernetesSecret",
                                "via": "imagePullSecret",
                                "discovered_via": "pod-config",
                            },
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
                        "node_name": node_name,
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
    """Convert pod object to a plain dict for escape + secret-consumer analysis."""
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
    if getattr(spec, "host_ipc", None):
        data["spec"]["hostIPC"] = spec.host_ipc
    if getattr(spec, "node_name", None):
        data["spec"]["nodeName"] = spec.node_name
    if getattr(spec, "image_pull_secrets", None):
        data["spec"]["imagePullSecrets"] = [
            {"name": ips.name} for ips in (spec.image_pull_secrets or []) if ips.name
        ]

    containers = []
    for c in (spec.containers or []) + (list(spec.init_containers or [])):
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
        if getattr(c, "env", None):
            envs = []
            for e in c.env or []:
                env_entry: dict[str, Any] = {"name": e.name}
                if e.value is not None:
                    env_entry["value"] = e.value
                if e.value_from and e.value_from.secret_key_ref:
                    env_entry["valueFrom"] = {
                        "secretKeyRef": {
                            "name": e.value_from.secret_key_ref.name,
                            "key": e.value_from.secret_key_ref.key,
                        }
                    }
                envs.append(env_entry)
            entry["env"] = envs
        if getattr(c, "env_from", None):
            entry["envFrom"] = [
                {"secretRef": {"name": ef.secret_ref.name}}
                for ef in (c.env_from or [])
                if ef.secret_ref and ef.secret_ref.name
            ]
        containers.append(entry)
    data["spec"]["containers"] = containers

    if spec.volumes:
        vols = []
        for v in spec.volumes:
            vol: dict[str, Any] = {"name": v.name}
            if v.host_path:
                vol["hostPath"] = {"path": v.host_path.path}
            if getattr(v, "secret", None) and v.secret:
                vol["secret"] = {"secretName": v.secret.secret_name}
            if getattr(v, "projected", None) and v.projected:
                sources = []
                for src in v.projected.sources or []:
                    if src.secret and src.secret.name:
                        sources.append({"secret": {"name": src.secret.name}})
                if sources:
                    vol["projected"] = {"sources": sources}
            if getattr(v, "csi", None) and v.csi:
                vol["csi"] = {
                    "driver": v.csi.driver,
                    "volumeAttributes": dict(v.csi.volume_attributes or {}),
                }
            vols.append(vol)
        data["spec"]["volumes"] = vols
    return data
