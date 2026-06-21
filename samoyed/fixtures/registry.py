from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPORTS_DIR = Path(__file__).resolve().parent / "reports"


@dataclass(frozen=True)
class FixtureSpec:
    id: str
    connector: str
    filename: str
    description: str
    demo: bool = True
    tags: tuple[str, ...] = ()


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
        }
        for s in specs
    ]


def get_fixture(fixture_id: str) -> FixtureSpec:
    for spec in FIXTURES:
        if spec.id == fixture_id:
            return spec
    known = ", ".join(s.id for s in FIXTURES)
    raise KeyError(f"Unknown fixture '{fixture_id}'. Known: {known}")


def fixture_path(fixture_id: str) -> Path:
    spec = get_fixture(fixture_id)
    path = REPORTS_DIR / spec.filename
    if not path.is_file():
        raise FileNotFoundError(f"Fixture file missing: {path}")
    return path


def read_fixture_bytes(fixture_id: str) -> bytes:
    return fixture_path(fixture_id).read_bytes()
