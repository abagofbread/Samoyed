from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPORTS_DIR = Path(__file__).resolve().parent / "reports"
LABS_DIR = Path(__file__).resolve().parent / "labs"


@dataclass(frozen=True)
class FixtureSpec:
    id: str
    connector: str
    filename: str
    description: str
    demo: bool = True
    tags: tuple[str, ...] = ()
    # When set, load via ``import-path`` semantics (tfstate tree + companion enrichments).
    lab_dir: str | None = None


FIXTURES: tuple[FixtureSpec, ...] = (
    FixtureSpec(
        id="lab-aws",
        connector="iam-report",
        filename="lab_leaked_credential.json",
        description="Leaked IAM user with assume-role and self-privesc (Samoyed client iam-report shape)",
        tags=("aws", "leaked-credential", "paths"),
    ),
    FixtureSpec(
        id="enterprise-aws",
        connector="iam-report",
        filename="enterprise_corp.json",
        description="Multi-hop corp environment: marketing EC2 → CI/CD → EKS/IRSA → vault (iam-report export)",
        tags=("aws", "enterprise", "multi-hop"),
    ),
    FixtureSpec(
        id="k8s-lab",
        connector="iam-report",
        filename="k8s_pod_escape.json",
        description="K8s pod escape + IRSA + secret access (iam-report with kubernetes provider)",
        tags=("kubernetes", "escape", "irsa"),
    ),
    FixtureSpec(
        id="host-pivot",
        connector="iam-report",
        filename="host_workstation_pivot.json",
        description="Compromised laptop with cached cloud sessions (iam-report + host pivot grants)",
        tags=("aws", "azure", "host"),
    ),
    FixtureSpec(
        id="aws-goat",
        connector="iam-report",
        filename="aws_goat_env.json",
        description="AWSGoat-style web tier (EC2/Lambda/RDS/S3 + EKS IRSA SA) — base for off-cloud credential enrichment demos",
        tags=("aws", "goat", "enrichment", "irsa", "credentials"),
    ),
    FixtureSpec(
        id="cloudfox-recon",
        connector="cloudfox",
        filename="cloudfox_recon.json",
        description="CloudFox-style findings export",
        tags=("aws", "cloudfox", "recon"),
    ),
    FixtureSpec(
        id="authz-aws",
        connector="aws-authz-details",
        filename="authz_minimal.json",
        description="Slice of iam:GetAccountAuthorizationDetails",
        tags=("aws", "authz", "enum"),
    ),
    FixtureSpec(
        id="cicd-supply-chain",
        connector="iam-report",
        filename="cicd_supply_chain.json",
        description="Leaked key WRITES artifact bucket; CI/CD and prod depend on it (dependency marking demos)",
        tags=("aws", "cicd", "supply-chain"),
    ),
    FixtureSpec(
        id="compute-exposure-lab",
        connector="iam-report",
        filename="lab_compute_exposure.json",
        description="SSRF Lambda → metadata → STS assume role → PCI bucket; internet write and mining-risk change analysis",
        tags=("aws", "compute", "ssrf", "pci", "change-impact"),
    ),
    FixtureSpec(
        id="azure-collected-sample",
        connector="iam-report",
        filename="azure_collected_sample.json",
        description="Sanitized live-shaped Azure iam-report (RBAC assignments, storage, Key Vault, web app MI)",
        tags=("azure", "iam-report", "sample"),
        demo=False,
    ),
    FixtureSpec(
        id="lab-azure",
        connector="iam-report",
        filename="lab_azure_rbac.json",
        description="Leaked CI service principal → dev secrets + web app → managed identity → prod Key Vault PII",
        tags=("azure", "rbac", "multi-hop", "keyvault"),
    ),
    FixtureSpec(
        id="vpc-peering-aws",
        connector="terraform",
        filename="vpc_peering_cross_account.tfstate",
        description="Dev EC2 (internet + IMDSv1 role) VPC-peered into prod PCI instance (cross-account)",
        tags=("aws", "terraform", "vpc-peering", "network", "cross-account"),
    ),
    FixtureSpec(
        id="corp-mesh-aws",
        connector="terraform",
        filename="corp_mesh_peering.tfstate",
        description=(
            "Multi-tier Terraform mesh: DMZ/App/PCI + shared/staging accounts, "
            "17 instances, 2 ALBs, 7 buckets, 4 VPC peerings"
        ),
        tags=("aws", "terraform", "vpc-peering", "network", "cross-account", "alb", "s3"),
    ),
    FixtureSpec(
        id="corp-mesh-gcp",
        connector="terraform",
        filename="corp_mesh_gcp.tfstate",
        description="Five-project GCP mesh: GCE bastion, Cloud Run, GCS crown jewel, SA impersonation, and WIF",
        tags=("gcp", "terraform", "vpc-peering", "network", "cross-project", "cloud-run", "gcs", "wif"),
    ),
    FixtureSpec(
        id="corp-mesh-azure",
        connector="terraform",
        filename="corp_mesh_azure.tfstate",
        description=(
            "Two-subscription Azure mesh: DMZ bastion MI → App Service MI → "
            "Key Vault crown jewel, VNet peering, Automation Owner path, ACR/storage"
        ),
        tags=("azure", "terraform", "vnet-peering", "network", "cross-subscription", "keyvault", "managed-identity"),
    ),
    FixtureSpec(
        id="lab-gcp",
        connector="iam-report",
        filename="lab_gcp_leaked_credential.json",
        description=(
            "Leaked CI SA → TokenCreator/actAs → Cloud Run/Function/GCE → "
            "cross-project PCI secrets and crown-jewel GCS"
        ),
        tags=("gcp", "leaked-credential", "iam", "paths", "cloud-run"),
    ),
    FixtureSpec(
        id="intercloud-host-pivot",
        connector="iam-report",
        filename="intercloud_host_pivot.json",
        description=(
            "Compromised laptop → AWS + GCP creds → Lambda/CI and Cloud Function "
            "IMDS chains → PCI secrets + WIF back into AWS shared services"
        ),
        tags=("aws", "gcp", "host", "intercloud", "wif"),
    ),
    FixtureSpec(
        id="wif-aws-gcp",
        connector="iam-report",
        filename="wif_aws_gcp.json",
        description=(
            "Multi-hop federation: leaked CI → impersonation → Cloud Build/Run → "
            "WIF into AWS → cross-account Secrets Manager/S3 (+ GKE WI side path)"
        ),
        tags=("aws", "gcp", "wif", "intercloud", "cloudbuild", "cross-account"),
    ),
    FixtureSpec(
        id="wif-aws-azure",
        connector="iam-report",
        filename="wif_aws_azure.json",
        description=(
            "Azure CI SP → WebApp MI → federated WIF into AWS → "
            "cross-account Secrets Manager/S3"
        ),
        tags=("aws", "azure", "wif", "intercloud", "webapp"),
    ),
    FixtureSpec(
        id="wif-gcp-azure",
        connector="iam-report",
        filename="wif_gcp_azure.json",
        description=(
            "Azure CI SP → FunctionApp MI → federated WIF into GCP → "
            "cross-project Secret Manager/GCS"
        ),
        tags=("gcp", "azure", "wif", "intercloud", "functionapp"),
    ),
    FixtureSpec(
        id="intercloud-tri-cloud",
        connector="iam-report",
        filename="intercloud_tri_cloud.json",
        description=(
            "Compromised CI host with AWS + GCP + Azure creds; WIF bridges touch all three providers"
        ),
        tags=("aws", "gcp", "azure", "host", "intercloud", "wif", "tri-cloud"),
    ),
    FixtureSpec(
        id="grand-tri-cloud",
        connector="terraform",
        filename="",
        lab_dir="grand-tri-cloud",
        description=(
            "Patient-zero corp-mesh-aws → bastion GCP app-deploy → Azure weak SP; "
            "per-env terraform + enrichment.json (import-path autoload)"
        ),
        tags=(
            "aws",
            "gcp",
            "azure",
            "terraform",
            "enrichment",
            "intercloud",
            "tri-cloud",
            "vpc-peering",
            "boundaries",
        ),
    ),
    FixtureSpec(
        id="bloodhound-entra-lab",
        connector="bloodhound",
        filename="bloodhound_entra_lab.json",
        description=(
            "AzureHound OpenGraph lab: App Admin MemberOf → AZAddSecret → SP → "
            "AZMGGrantRole / GlobalAdmin"
        ),
        tags=("azure", "bloodhound", "entra", "add-secret", "global-admin"),
    ),
    FixtureSpec(
        id="hybrid-mimikatz-entra",
        connector="bloodhound",
        filename="hybrid_mimikatz_entra.json",
        description=(
            "Hybrid BloodHound story: HasSession (LSASS/mimikatz) → SyncedToADUser → "
            "Entra group → Key Vault secrets"
        ),
        tags=("azure", "ad", "bloodhound", "hybrid", "mimikatz", "keyvault"),
    ),
)


def list_fixtures(*, demo_only: bool = False) -> list[dict[str, Any]]:
    specs = FIXTURES
    if demo_only:
        specs = tuple(s for s in specs if s.demo)
    return [
        {
            "id": s.id,
            "connector": s.connector,
            "filename": s.filename,
            "description": s.description,
            "tags": list(s.tags),
            "demo": s.demo,
            **({"lab_dir": s.lab_dir} if s.lab_dir else {}),
        }
        for s in specs
    ]


def get_fixture(fixture_id: str) -> FixtureSpec:
    for spec in FIXTURES:
        if spec.id == fixture_id:
            return spec
    known = ", ".join(s.id for s in FIXTURES)
    raise KeyError(f"Unknown fixture '{fixture_id}'. Known: {known}")


def fixture_lab_path(fixture_id: str) -> Path | None:
    spec = get_fixture(fixture_id)
    if not spec.lab_dir:
        return None
    path = LABS_DIR / spec.lab_dir
    if not path.is_dir():
        raise FileNotFoundError(f"Fixture lab directory missing: {path}")
    return path


def fixture_path(fixture_id: str) -> Path:
    lab = fixture_lab_path(fixture_id)
    if lab is not None:
        return lab
    spec = get_fixture(fixture_id)
    path = REPORTS_DIR / spec.filename
    if not path.is_file():
        raise FileNotFoundError(f"Fixture file missing: {path}")
    return path


def read_fixture_bytes(fixture_id: str) -> bytes:
    path = fixture_path(fixture_id)
    if path.is_dir():
        raise IsADirectoryError(f"Fixture '{fixture_id}' is a lab directory; use load_fixture_session")
    return path.read_bytes()
