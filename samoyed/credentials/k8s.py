from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from samoyed.cloud.concepts import CloudProvider
from samoyed.cloud.providers import make_scope_id
from samoyed.credentials.protocol import ScopeBoundary


def _require_kubernetes():
    try:
        from kubernetes import client, config
    except ImportError as exc:
        raise ImportError("Install Kubernetes support: pip install 'samoyed[k8s]'") from exc
    return client, config


class K8sCredential:
    provider = CloudProvider.KUBERNETES

    def __init__(
        self,
        *,
        kubeconfig: Path | str | None = None,
        context: str | None = None,
        in_cluster: bool = False,
    ) -> None:
        client, config = _require_kubernetes()
        if in_cluster:
            config.load_incluster_config()
        else:
            kube_path = kubeconfig or os.environ.get("KUBECONFIG")
            if kube_path:
                config.load_kube_config(config_file=str(kube_path), context=context)
            else:
                config.load_kube_config(context=context)

        self._client = client
        self._context_name, self._cluster_name, self._user_name = self._active_context(config)
        self._core = client.CoreV1Api()
        self._rbac = client.RbacAuthorizationV1Api()
        self._auth = client.AuthorizationV1Api()
        self._caller: dict[str, Any] | None = None

    @classmethod
    def from_kubeconfig(
        cls,
        path: Path | str | None = None,
        *,
        context: str | None = None,
    ) -> K8sCredential:
        return cls(kubeconfig=path, context=context)

    @classmethod
    def in_cluster(cls) -> K8sCredential:
        return cls(in_cluster=True)

    def _active_context(self, config_mod) -> tuple[str, str, str]:
        contexts, active = config_mod.list_kube_config_contexts()
        if not active:
            raise RuntimeError("No active kubeconfig context")
        context_name = active["name"]
        cluster_name = active["context"].get("cluster", "unknown")
        user_name = active["context"].get("user", "unknown")
        return context_name, cluster_name, user_name

    def client(self, service: str, region: str | None = None) -> Any:
        del region
        if service in {"core", "v1", "core/v1"}:
            return self._core
        if service in {"rbac", "rbac.authorization.k8s.io"}:
            return self._rbac
        if service in {"auth", "authorization.k8s.io"}:
            return self._auth
        raise ValueError(f"Unknown Kubernetes API group: {service}")

    def get_caller_identity(self) -> dict[str, Any]:
        if self._caller is None:
            native_id = user_native_id(self._user_name)
            username = self._user_name
            try:
                review = self._auth.create_self_subject_review(
                    body={"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectReview"}
                )
                status = review.status
                if status and status.user_info:
                    username = status.user_info.username or username
                    if status.user_info.uid:
                        native_id = f"kubernetes:uid:{status.user_info.uid}"
            except Exception:
                pass
            self._caller = {
                "username": username,
                "native_id": native_id,
                "context": self._context_name,
                "cluster": self._cluster_name,
            }
        return self._caller

    def resolve_scope(self) -> ScopeBoundary:
        ident = self.get_caller_identity()
        scope_id = make_scope_id(CloudProvider.KUBERNETES, "cluster", self._cluster_name)
        return ScopeBoundary(
            provider=CloudProvider.KUBERNETES,
            scope_id=scope_id,
            display_name=f"Kubernetes cluster {self._cluster_name}",
            properties={
                "cluster": self._cluster_name,
                "context": self._context_name,
                "user": ident["username"],
                "native_id": ident["native_id"],
            },
        )

    def fingerprint(self) -> str:
        return self.get_caller_identity()["native_id"]


def sa_native_id(namespace: str, name: str) -> str:
    return f"kubernetes:serviceaccount:{namespace}:{name}"


def user_native_id(username: str) -> str:
    return f"kubernetes:user:{username}"


def pod_native_id(namespace: str, name: str) -> str:
    return f"kubernetes:pod:{namespace}:{name}"


def namespace_native_id(name: str) -> str:
    return f"kubernetes:namespace:{name}"


def cluster_api_native_id(cluster: str) -> str:
    return f"kubernetes:api:{cluster}"
