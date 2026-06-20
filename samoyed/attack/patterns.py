from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from samoyed.cloud.concepts import CloudProvider

TargetKind = Literal[
    "any_role",
    "any_user",
    "admin_outcome",
    "assumable_roles",
    "execution_roles",
    "stored_identities",
]


@dataclass(frozen=True)
class AttackPattern:
    """Multi-action privilege-escalation pattern (HackTricks / Rhino Security style)."""

    id: str
    name: str
    description: str
    provider: CloudProvider
    required_actions: frozenset[str]
    target: TargetKind
    severity: str = "critical"
    source: str = "hacktricks"


# AWS patterns — curated from HackTricks privesc sections (IAM, Lambda, CFN, EC2, STS).
AWS_ATTACK_PATTERNS: tuple[AttackPattern, ...] = (
    AttackPattern(
        id="aws-iam-attach-user-policy",
        name="Attach policy to user",
        description="Attach a managed policy (e.g. AdministratorAccess) to any IAM user.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:AttachUserPolicy"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="aws-iam-put-user-policy",
        name="Inline policy on user",
        description="Put an inline admin policy on any IAM user.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PutUserPolicy"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="aws-iam-attach-role-policy",
        name="Attach policy to role",
        description="Attach a managed policy to a role, then assume or use that role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:AttachRolePolicy"}),
        target="any_role",
    ),
    AttackPattern(
        id="aws-iam-put-role-policy",
        name="Inline policy on role",
        description="Put an inline admin policy on any IAM role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PutRolePolicy"}),
        target="any_role",
    ),
    AttackPattern(
        id="aws-iam-create-access-key",
        name="Create access key for user",
        description="Create access keys for another user and use their permissions.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:CreateAccessKey"}),
        target="any_user",
    ),
    AttackPattern(
        id="aws-iam-create-login-profile",
        name="Console login for user",
        description="Create or reset console password for another IAM user.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:CreateLoginProfile"}),
        target="any_user",
    ),
    AttackPattern(
        id="aws-iam-update-login-profile",
        name="Reset console password",
        description="Update login profile / password for another IAM user.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:UpdateLoginProfile"}),
        target="any_user",
    ),
    AttackPattern(
        id="aws-iam-create-policy-version",
        name="Policy version rollback",
        description="Create a new policy version with admin actions and set as default.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:CreatePolicyVersion"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="aws-iam-set-default-policy-version",
        name="Activate permissive policy version",
        description="Switch default IAM policy version to a more permissive one.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:SetDefaultPolicyVersion"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="aws-lambda-create-invoke",
        name="Lambda create + invoke (PassRole)",
        description="Create a Lambda with a passed role and invoke it to run as that role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset(
            {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"}
        ),
        target="any_role",
    ),
    AttackPattern(
        id="aws-lambda-create-invoke-url",
        name="Lambda create + invoke URL (PassRole)",
        description="Create a Lambda with PassRole and invoke via function URL.",
        provider=CloudProvider.AWS,
        required_actions=frozenset(
            {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunctionUrl"}
        ),
        target="any_role",
    ),
    AttackPattern(
        id="aws-lambda-update-code",
        name="Lambda code takeover",
        description="Update Lambda function code and steal execution role credentials.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"lambda:UpdateFunctionCode"}),
        target="execution_roles",
    ),
    AttackPattern(
        id="aws-lambda-add-permission",
        name="Lambda resource policy self-grant",
        description="Add permissive resource policy on Lambda, then update code and invoke.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"lambda:AddPermission", "lambda:UpdateFunctionCode"}),
        target="execution_roles",
    ),
    AttackPattern(
        id="aws-cloudformation-create-stack",
        name="CloudFormation stack (PassRole)",
        description="Deploy a CloudFormation stack that runs actions as a passed admin role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "cloudformation:CreateStack"}),
        target="any_role",
    ),
    AttackPattern(
        id="aws-ec2-run-instances",
        name="EC2 RunInstances (PassRole)",
        description="Launch EC2 with an instance profile / role to steal credentials via IMDS.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "ec2:RunInstances"}),
        target="any_role",
    ),
    AttackPattern(
        id="aws-states-test-state",
        name="Step Functions TestState (PassRole)",
        description="Test a state machine state with an arbitrary passed IAM role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "states:TestState"}),
        target="any_role",
    ),
)

GCP_ATTACK_PATTERNS: tuple[AttackPattern, ...] = (
    AttackPattern(
        id="gcp-sa-actas-create-function",
        name="Cloud Function + actAs",
        description="Create a Cloud Function running as a more privileged service account.",
        provider=CloudProvider.GCP,
        required_actions=frozenset(
            {"gcp:iam.serviceAccounts.actAs", "gcp:cloudfunctions.functions.create"}
        ),
        target="execution_roles",
    ),
    AttackPattern(
        id="gcp-sa-actas-deploy",
        name="Deploy workload as service account",
        description="Deploy Cloud Run / GCE / GCF using iam.serviceAccounts.actAs.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.serviceAccounts.actAs", "gcp:run.services.create"}),
        target="execution_roles",
    ),
    AttackPattern(
        id="gcp-sa-key-create",
        name="Service account key creation",
        description="Create a key for a privileged service account and authenticate offline.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.serviceAccountKeys.create"}),
        target="any_role",
    ),
    AttackPattern(
        id="gcp-set-iam-policy",
        name="Project IAM policy binding",
        description="setIamPolicy on project/folder/org grants arbitrary roles.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:resourcemanager.projects.setIamPolicy"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="gcp-token-creator",
        name="Service account token mint",
        description="roles/iam.serviceAccountTokenCreator — mint OAuth tokens for another SA.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.serviceAccounts.getAccessToken"}),
        target="any_role",
    ),
)

AZURE_ATTACK_PATTERNS: tuple[AttackPattern, ...] = (
    AttackPattern(
        id="azure-role-assignment-write",
        name="Grant RBAC role assignment",
        description="Microsoft.Authorization/roleAssignments/write — assign Owner/Contributor.",
        provider=CloudProvider.AZURE,
        required_actions=frozenset({"azure:authorization.roleAssignments.write"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="azure-uami-assign",
        name="Assign user-assigned managed identity",
        description="Attach a privileged managed identity to a VM or app you control.",
        provider=CloudProvider.AZURE,
        required_actions=frozenset(
            {"azure:managedIdentity.userAssignedIdentities.assign", "azure:compute.virtualMachines.write"}
        ),
        target="execution_roles",
    ),
    AttackPattern(
        id="azure-run-command",
        name="VM Run Command",
        description="Run arbitrary script on VM via Run Command — steal IMDS / MSI token.",
        provider=CloudProvider.AZURE,
        required_actions=frozenset({"azure:compute.virtualMachines.runCommand"}),
        target="execution_roles",
    ),
    AttackPattern(
        id="azure-keyvault-access-policy",
        name="Key Vault access policy write",
        description="Add yourself to Key Vault access policies (legacy model).",
        provider=CloudProvider.AZURE,
        required_actions=frozenset({"azure:keyvault.vaults.write"}),
        target="admin_outcome",
    ),
)

HOST_ATTACK_PATTERNS: tuple[AttackPattern, ...] = (
    AttackPattern(
        id="host-interactive-session",
        name="Interactive session token theft",
        description="LSASS / mimikatz / token duplication on a workstation with a logged-in cloud user.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"host:interactive-session"}),
        target="stored_identities",
    ),
    AttackPattern(
        id="host-credential-store",
        name="Cached credential store theft",
        description="Read ~/.aws, ~/.azure, gcloud ADC, or kubeconfig from a compromised host.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"host:credential-store"}),
        target="stored_identities",
    ),
)

K8S_ATTACK_PATTERNS: tuple[AttackPattern, ...] = (
    AttackPattern(
        id="k8s-cluster-admin-binding",
        name="Cluster-admin RBAC",
        description="Effective cluster-admin or wildcard RBAC over all resources.",
        provider=CloudProvider.KUBERNETES,
        required_actions=frozenset({"rbac:cluster-admin"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="k8s-secrets-write",
        name="Write cluster secrets",
        description="Create/update secrets cluster-wide — credential theft and persistence.",
        provider=CloudProvider.KUBERNETES,
        required_actions=frozenset({"rbac:secrets:write"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="k8s-pods-exec",
        name="Exec into pods",
        description="Exec into pods to steal service account tokens and cloud bindings.",
        provider=CloudProvider.KUBERNETES,
        required_actions=frozenset({"rbac:pods:exec"}),
        target="any_role",
    ),
)


def patterns_for_provider(provider: CloudProvider) -> tuple[AttackPattern, ...]:
    if provider == CloudProvider.AWS:
        return AWS_ATTACK_PATTERNS + HOST_ATTACK_PATTERNS
    if provider == CloudProvider.GCP:
        return GCP_ATTACK_PATTERNS + HOST_ATTACK_PATTERNS
    if provider == CloudProvider.AZURE:
        return AZURE_ATTACK_PATTERNS + HOST_ATTACK_PATTERNS
    if provider == CloudProvider.KUBERNETES:
        return K8S_ATTACK_PATTERNS + HOST_ATTACK_PATTERNS
    return HOST_ATTACK_PATTERNS
