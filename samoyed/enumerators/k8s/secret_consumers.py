"""Extract secret / configMap consumer refs from a pod spec dict."""

from __future__ import annotations

from typing import Any


def secret_refs_from_pod_spec(spec: dict[str, Any]) -> list[dict[str, str]]:
    """Return [{namespace, name, via}] for secrets a pod mounts or injects."""
    meta = spec.get("metadata") or {}
    namespace = meta.get("namespace", "default")
    pod_spec = spec.get("spec") or {}
    refs: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, via: str, ns: str | None = None) -> None:
        if not name:
            return
        key = f"{ns or namespace}:{name}"
        if key in seen:
            return
        seen.add(key)
        refs.append({"namespace": ns or namespace, "name": name, "via": via})

    # volumes[].secret / projected
    for vol in pod_spec.get("volumes") or []:
        sec = vol.get("secret") or {}
        if sec.get("secretName"):
            add(sec["secretName"], "volume")
        csi = vol.get("csi") or {}
        if csi.get("driver") and "secret" in str(csi.get("driver", "")).lower():
            # CSI attrs sometimes carry secretProviderClass — still flag as consumer soft signal
            attrs = csi.get("volumeAttributes") or {}
            spc = attrs.get("secretProviderClass") or attrs.get("secretProviderClassName")
            if spc:
                add(spc, "csi-secret-store")
        for src in (vol.get("projected") or {}).get("sources") or []:
            ps = src.get("secret") or {}
            if ps.get("name"):
                add(ps["name"], "projected")

    containers = list(pod_spec.get("containers") or []) + list(pod_spec.get("initContainers") or [])
    for container in containers:
        for env in container.get("env") or []:
            ref = (env.get("valueFrom") or {}).get("secretKeyRef") or {}
            if ref.get("name"):
                add(ref["name"], "env-secretKeyRef")
        for env_from in container.get("envFrom") or []:
            ref = env_from.get("secretRef") or {}
            if ref.get("name"):
                add(ref["name"], "envFrom-secretRef")

    # Service account token projected volumes are secrets of type kubernetesServiceAccountToken —
    # skip auto SA token names when obvious; still include explicit secretName volumes.
    return refs


def image_pull_secret_names(spec: dict[str, Any]) -> list[str]:
    pod_spec = spec.get("spec") or {}
    names: list[str] = []
    for entry in pod_spec.get("imagePullSecrets") or []:
        if entry.get("name"):
            names.append(entry["name"])
    return names
