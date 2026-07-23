from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MaterialKindSpec:
    """Predefined collector finding → graph relationship mapping.

    ``requires_target`` means an identity unlock (UNLOCKS) is expected for full
    blast extension. Materials still attach via HAS_MATERIAL without it.
    """

    kind: str
    display_name: str
    description: str
    host_rel: str
    unlock_rel: str
    extends_blast_to: str
    requires_target: bool = True
    assessor: str = "rule"


MATERIAL_KINDS: dict[str, MaterialKindSpec] = {
    "aws_access_key_env": MaterialKindSpec(
        kind="aws_access_key_env",
        display_name="AWS access key",
        description="AWS access key id in process or config environment variables.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="AWS IAM principal",
    ),
    "aws_secret_key_env": MaterialKindSpec(
        kind="aws_secret_key_env",
        display_name="AWS secret access key",
        description="AWS secret access key stored in environment or config.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="AWS IAM principal",
    ),
    "aws_session_token_env": MaterialKindSpec(
        kind="aws_session_token_env",
        display_name="AWS session token",
        description="Temporary AWS session token paired with access key material.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="AWS IAM principal",
    ),
    "kubeconfig_file": MaterialKindSpec(
        kind="kubeconfig_file",
        display_name="Kubeconfig file",
        description="Cluster credentials on disk or in a mounted volume.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="Kubernetes API / cluster identity",
    ),
    "k8s_service_account_token": MaterialKindSpec(
        kind="k8s_service_account_token",
        display_name="Kubernetes service account token",
        description="Projected or legacy SA token usable against the Kubernetes API.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="Kubernetes service account RBAC",
    ),
    "k8s_client_cert": MaterialKindSpec(
        kind="k8s_client_cert",
        display_name="Kubernetes client certificate",
        description="Client cert/key pair granting API access (often cluster-admin).",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="Kubernetes API",
    ),
    "gcp_service_account_json": MaterialKindSpec(
        kind="gcp_service_account_json",
        display_name="GCP service account key (JSON)",
        description="GCP service account key file or embedded JSON.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="GCP service account",
    ),
    "azure_client_secret_env": MaterialKindSpec(
        kind="azure_client_secret_env",
        display_name="Azure client secret (environment)",
        description="Azure AD application client secret in environment or config.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="Azure service principal",
    ),
    "database_connection_string": MaterialKindSpec(
        kind="database_connection_string",
        display_name="Database connection string",
        description="Connection string or DSN with embedded credentials.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="Database / datastore",
        requires_target=False,
    ),
    "generic_credential_file": MaterialKindSpec(
        kind="generic_credential_file",
        display_name="Hardcoded credential",
        description="Password, key, or other credential embedded in config/source.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="Unknown identity",
        requires_target=False,
    ),
    "none_observed": MaterialKindSpec(
        kind="none_observed",
        display_name="No credentials observed",
        description="Collector interviewed the node and found no pivot material.",
        host_rel="HAS_MATERIAL",
        unlock_rel="UNLOCKS",
        extends_blast_to="None",
        requires_target=False,
    ),
}


def export_catalog() -> dict[str, Any]:
    return {
        "enrichment_version": 1,
        "material_kinds": [
            {
                "kind": spec.kind,
                "display_name": spec.display_name,
                "description": spec.description,
                "host_rel": spec.host_rel,
                "unlock_rel": spec.unlock_rel,
                "extends_blast_to": spec.extends_blast_to,
                "requires_target": spec.requires_target,
            }
            for spec in MATERIAL_KINDS.values()
        ],
    }


def get_material_kind(kind: str) -> MaterialKindSpec:
    key = kind.strip()
    if key not in MATERIAL_KINDS:
        known = ", ".join(sorted(MATERIAL_KINDS))
        raise ValueError(f"Unknown material kind '{kind}'. Known kinds: {known}")
    return MATERIAL_KINDS[key]
