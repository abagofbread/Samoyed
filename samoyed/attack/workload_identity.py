"""Validate GKE Workload Identity annotations against GCP service-account IAM."""

from __future__ import annotations

from samoyed.graph.builder import GraphBuilder


def enrich_workload_identity(builder: GraphBuilder) -> dict[str, int]:
    """Stamp annotation edges only when a matching workloadIdentityUser grant exists."""
    graph = builder.snapshot
    validated = 0
    unvalidated = 0
    bindings = [
        node.props
        for node in graph.nodes.values()
        if node.props.get("role") == "roles/iam.workloadIdentityUser"
    ]
    for edge in graph.edges:
        if edge.rel_type != "PROJECTS_TO" or edge.props.get("binding_type") != "WorkloadIdentity":
            continue
        src = graph.nodes.get(edge.src_id)
        target = graph.nodes.get(edge.dst_id)
        if not src or not target:
            continue
        native = str(src.props.get("native_id") or "")
        parts = native.split(":")
        if len(parts) < 4 or parts[:2] != ["kubernetes", "serviceaccount"]:
            edge.props["trust_validated"] = False
            unvalidated += 1
            continue
        namespace, sa_name = parts[2], parts[3]
        email = str(target.props.get("email") or target.props.get("native_id") or "").removeprefix(
            "gcp:serviceaccount:"
        )
        project = email.split("@", 1)[-1].split(".", 1)[0] if "@" in email else ""
        principal = f"serviceAccount:{project}.svc.id.goog[{namespace}/{sa_name}]"
        principal_set = f"principalSet://iam.googleapis.com/projects/{project}/locations/global/workloadIdentityPools/"
        is_valid = any(
            str(binding.get("target_service_account") or "") == email
            and any(
                member == principal or member.startswith(principal_set)
                for member in binding.get("members") or []
            )
            for binding in bindings
        )
        edge.props["trust_validated"] = is_valid
        edge.props["mechanism"] = "wif"
        if is_valid:
            validated += 1
        else:
            unvalidated += 1
    return {
        "workload_identity_validated": validated,
        "workload_identity_unvalidated": unvalidated,
    }
