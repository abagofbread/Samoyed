from __future__ import annotations

from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.k8s import cluster_api_native_id, sa_native_id, user_native_id
from samoyed.credentials.protocol import EnumContext
from samoyed.enumerators.k8s.helpers import (
    DANGEROUS_CLUSTER_ROLES,
    GRANT_TARGET_CONCEPT,
    call_k8s,
    rule_grants,
)


class K8sIdentityEnumerator:
    concept = ConceptType.IDENTITY
    name = "k8s-identity"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        caller_id = ctx.scope.properties.get("native_id", "")
        caller_user = ctx.scope.properties.get("user", "")

        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.KUBERNETES,
            native_id=caller_id or user_native_id(caller_user),
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": "User",
                "username": caller_user,
                "is_caller": True,
                "display_name": caller_user,
            },
            evidence=Evidence("authorization.k8s.io:SelfSubjectReview", {"user": caller_user}),
            confidence=ConfidenceType.EXPLICIT,
        )

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
                name = sa.metadata.name
                native_id = sa_native_id(namespace, name)
                yield ConceptArtifact(
                    concept_type=ConceptType.IDENTITY,
                    provider=CloudProvider.KUBERNETES,
                    native_id=native_id,
                    scope_id=ctx.scope.scope_id,
                    properties={
                        "native_kind": "ServiceAccount",
                        "namespace": namespace,
                        "name": name,
                        "display_name": f"{namespace}/{name}",
                    },
                    evidence=Evidence("core/v1:serviceaccounts", {"namespace": namespace, "name": name}),
                )


class K8sRbacEnumerator:
    concept = ConceptType.ENTITLEMENT
    name = "k8s-rbac"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        cred = ctx.credentials
        rbac = cred.client("rbac")  # type: ignore[attr-defined]
        cluster = ctx.scope.properties.get("cluster", "cluster")
        api_id = cluster_api_native_id(cluster)

        role_cache: dict[str, list[dict[str, Any]]] = {}

        def get_role_rules(kind: str, name: str, namespace: str | None) -> list[dict[str, Any]]:
            key = f"{kind}:{namespace or ''}:{name}"
            if key in role_cache:
                return role_cache[key]
            rules: list[dict[str, Any]] = []
            if kind == "ClusterRole":
                obj = call_k8s(
                    ctx,
                    operation=f"rbac:clusterroles:{name}",
                    call=lambda: rbac.read_cluster_role(name=name),
                )
                if obj:
                    rules = [r.to_dict() for r in (obj.rules or [])]
            else:
                obj = call_k8s(
                    ctx,
                    operation=f"rbac:roles:{namespace}:{name}",
                    call=lambda: rbac.read_namespaced_role(name=name, namespace=namespace or "default"),
                )
                if obj:
                    rules = [r.to_dict() for r in (obj.rules or [])]
            role_cache[key] = rules
            return rules

        cr_list = call_k8s(ctx, operation="rbac:clusterroles", call=lambda: rbac.list_cluster_role())
        if cr_list:
            for cr in cr_list.items:
                name = cr.metadata.name
                rules = [r.to_dict() for r in (cr.rules or [])]
                role_cache[f"ClusterRole::{name}"] = rules

        crb_list = call_k8s(
            ctx, operation="rbac:clusterrolebindings", call=lambda: rbac.list_cluster_role_binding()
        )
        if crb_list:
            for binding in crb_list.items:
                ref = binding.role_ref
                rules = get_role_rules(ref.kind, ref.name, None)
                subjects = [_subject_native_id(s) for s in (binding.subjects or [])]
                yield from self._binding_grants(
                    ctx,
                    binding_kind=ref.kind,
                    role_name=ref.name,
                    rules=rules,
                    subjects=[s for s in subjects if s],
                    api_id=api_id,
                    binding_name=binding.metadata.name,
                )

        core = cred.client("core")  # type: ignore[attr-defined]
        ns_list = call_k8s(ctx, operation="core/v1:namespaces", call=lambda: core.list_namespace())
        namespaces = [ns.metadata.name for ns in ns_list.items] if ns_list else ["default"]

        for namespace in namespaces:
            rb_list = call_k8s(
                ctx,
                operation=f"rbac:rolebindings:{namespace}",
                call=lambda ns=namespace: rbac.list_namespaced_role_binding(namespace=ns),
            )
            if not rb_list:
                continue
            for binding in rb_list.items:
                ref = binding.role_ref
                rules = get_role_rules(ref.kind, ref.name, namespace if ref.kind == "Role" else None)
                subjects = [_subject_native_id(s) for s in (binding.subjects or [])]
                yield from self._binding_grants(
                    ctx,
                    binding_kind=ref.kind,
                    role_name=ref.name,
                    rules=rules,
                    subjects=[s for s in subjects if s],
                    api_id=api_id,
                    binding_name=f"{namespace}/{binding.metadata.name}",
                    namespace=namespace,
                )

    def _binding_grants(
        self,
        ctx: EnumContext,
        *,
        binding_kind: str,
        role_name: str,
        rules: list[dict[str, Any]],
        subjects: list[str],
        api_id: str,
        binding_name: str = "",
        namespace: str | None = None,
    ) -> Iterator[ConceptArtifact]:
        grants = rule_grants(rules)
        if role_name in DANGEROUS_CLUSTER_ROLES and not any(
            g[0] == "CAN_ACCESS" and g[1] == "ManagementEndpoint" for g in grants
        ):
            grants.append(("CAN_ACCESS", "ManagementEndpoint", None))

        if not grants:
            return

        native_id = f"kubernetes:rbac:{binding_kind}:{namespace or 'cluster'}:{binding_name or role_name}"
        edges: list[ConceptEdge] = []
        for subject in subjects:
            for rel_type, target_concept, action in grants:
                concept = GRANT_TARGET_CONCEPT.get(target_concept)
                if target_concept == "ManagementEndpoint":
                    target_id = api_id
                elif concept:
                    target_id = f"kubernetes:{target_concept.lower()}:*"
                else:
                    continue
                edge_props: dict[str, Any] = {
                    "role": role_name,
                    "binding": binding_name or role_name,
                    "namespace": namespace,
                    "rbac_rule": rules,
                    "source": "k8s-rbac-enum",
                }
                if action:
                    edge_props["action"] = action
                edges.append(
                    ConceptEdge(
                        rel_type=rel_type,
                        src_native_id=subject,
                        target_native_id=target_id,
                        target_concept_type=concept or ConceptType.MANAGEMENT_ENDPOINT,
                        props=edge_props,
                        confidence=ConfidenceType.WILDCARD
                        if rel_type in {"READS", "CONTROLS"} and target_id.endswith("*")
                        else ConfidenceType.EXPLICIT,
                    )
                )

        if not edges:
            return

        yield ConceptArtifact(
            concept_type=ConceptType.ENTITLEMENT,
            provider=CloudProvider.KUBERNETES,
            native_id=native_id,
            scope_id=ctx.scope.scope_id,
            properties={
                "native_kind": binding_kind,
                "role_name": role_name,
                "binding_name": binding_name,
                "namespace": namespace,
                "subjects": subjects,
                "rules": rules,
            },
            evidence=Evidence("rbac.authorization.k8s.io:binding", {"role": role_name, "binding": binding_name}),
            edges=edges,
        )


def _subject_native_id(subject) -> str | None:
    kind = subject.kind
    name = subject.name
    namespace = getattr(subject, "namespace", None)
    if kind == "ServiceAccount":
        return sa_native_id(namespace or "default", name)
    if kind == "User":
        return user_native_id(name)
    if kind == "Group":
        return f"kubernetes:group:{name}"
    return None
