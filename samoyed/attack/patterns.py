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
    "runtime_bindings",
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
    # MITRE T1098 / T1578 / T1021 — cloud compute & account manipulation
    AttackPattern(
        id="aws-iam-add-user-to-group",
        name="Add user to privileged group",
        description="Add self or another user to a group with elevated IAM permissions.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:AddUserToGroup"}),
        target="admin_outcome",
        source="mitre-attack",
    ),
    AttackPattern(
        id="aws-iam-update-assume-role-policy",
        name="Modify role trust policy",
        description="Update AssumeRole policy to allow attacker-controlled principal.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:UpdateAssumeRolePolicy"}),
        target="any_role",
        source="mitre-attack",
    ),
    AttackPattern(
        id="aws-ssm-send-command",
        name="SSM SendCommand on EC2",
        description="Execute commands on EC2 via SSM — steal instance profile credentials (T1021.008).",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"ssm:SendCommand"}),
        target="runtime_bindings",
        source="mitre-attack",
    ),
    AttackPattern(
        id="aws-ec2-create-snapshot",
        name="EBS snapshot creation",
        description="Create volume snapshot for offline credential / data access (T1578.001).",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"ec2:CreateSnapshot"}),
        target="admin_outcome",
        source="mitre-attack",
    ),
    AttackPattern(
        id="aws-ec2-modify-instance-attribute",
        name="Modify EC2 instance attribute",
        description="Change userData or IAM profile on running instance (T1578.005).",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"ec2:ModifyInstanceAttribute"}),
        target="runtime_bindings",
        source="mitre-attack",
    ),
    AttackPattern(
        id="aws-ecs-run-task",
        name="ECS RunTask (PassRole)",
        description="Launch ECS task with a passed privileged task role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "ecs:RunTask"}),
        target="any_role",
        source="mitre-attack",
    ),
    AttackPattern(
        id="aws-iam-star",
        name="IAM wildcard (iam:*)",
        description="Full IAM control — create users, attach policies, forge lasting admin access.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:*"}),
        target="admin_outcome",
        source="high-value-catalog",
    ),
    AttackPattern(
        id="aws-star-admin",
        name="Administrator wildcard (*)",
        description="Action * grants unrestricted account control including IAM and resource ownership.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"*"}),
        target="admin_outcome",
        source="high-value-catalog",
    ),
    AttackPattern(
        id="aws-disable-cloudtrail",
        name="Disable CloudTrail logging",
        description="Stop or delete CloudTrail to evade detection (T1562.008).",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"cloudtrail:StopLogging"}),
        target="admin_outcome",
        severity="high",
        source="mitre-attack",
    ),
    # --- SkyArk AWStealth + Rhino IAM privesc gaps ---
    AttackPattern(
        id="aws-iam-attach-group-policy",
        name="Attach policy to group (SkyArk ShadowAttachGroupPolicy)",
        description="Attach AdministratorAccess (or any managed policy) to an IAM group; all members inherit admin.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:AttachGroupPolicy"}),
        target="admin_outcome",
        source="skyark",
    ),
    AttackPattern(
        id="aws-iam-put-group-policy",
        name="Inline policy on group (SkyArk ShadowPutGroupPolicy)",
        description="Put an arbitrary inline admin policy on a group the principal can influence.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PutGroupPolicy"}),
        target="admin_outcome",
        source="skyark",
    ),
    AttackPattern(
        id="aws-iam-create-policy",
        name="Create IAM policy (SkyArk ShadowCreatePolicy)",
        description="Create a custom managed policy with admin actions, then attach it via a companion grant.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:CreatePolicy"}),
        target="admin_outcome",
        severity="high",
        source="skyark",
    ),
    AttackPattern(
        id="aws-iam-passrole-instance-profile",
        name="PassRole into instance profile (SkyArk ShadowModifyInstanceProfiles)",
        description="Add a privileged role to an instance profile / create one — EC2 then runs as that role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "iam:AddRoleToInstanceProfile"}),
        target="any_role",
        source="skyark",
    ),
    AttackPattern(
        id="aws-iam-create-instance-profile-passrole",
        name="Create instance profile + PassRole",
        description="Create a new instance profile, attach a privileged role, and pair with EC2 association.",
        provider=CloudProvider.AWS,
        required_actions=frozenset(
            {"iam:PassRole", "iam:CreateInstanceProfile", "iam:AddRoleToInstanceProfile"}
        ),
        target="any_role",
        source="skyark",
    ),
    AttackPattern(
        id="aws-ec2-associate-instance-profile",
        name="Associate IAM instance profile on EC2",
        description="Swap an EC2 instance's profile to a privileged role (often with PassRole).",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "ec2:AssociateIamInstanceProfile"}),
        target="any_role",
        source="skyark",
    ),
    AttackPattern(
        id="aws-ec2-passrole-ssm",
        name="PassRole + RunInstances + SSM (AWSGoat-style)",
        description="Launch EC2 with a privileged profile then steal creds / run commands via SSM.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "ec2:RunInstances", "ssm:SendCommand"}),
        target="any_role",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-glue-passrole-dev-endpoint",
        name="Glue Dev Endpoint PassRole (SkyArk ShadowGlueDevEndpoint)",
        description="Create a Glue development endpoint with a privileged role and SSH into it.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "glue:CreateDevEndpoint"}),
        target="any_role",
        source="skyark",
    ),
    AttackPattern(
        id="aws-glue-update-dev-endpoint",
        name="Update Glue Dev Endpoint SSH key (Rhino #20)",
        description="Replace SSH public key on an existing Glue endpoint and inherit its role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"glue:UpdateDevEndpoint"}),
        target="execution_roles",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-datapipeline-passrole",
        name="Data Pipeline PassRole (SkyArk ShadowDataPipeline)",
        description="Create/update a pipeline that runs arbitrary actions as a passed role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset(
            {"iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"}
        ),
        target="any_role",
        source="skyark",
    ),
    AttackPattern(
        id="aws-sagemaker-passrole-notebook",
        name="SageMaker notebook PassRole (Rhino #27)",
        description="Create a Jupyter notebook with a privileged role and open a presigned URL.",
        provider=CloudProvider.AWS,
        required_actions=frozenset(
            {
                "iam:PassRole",
                "sagemaker:CreateNotebookInstance",
                "sagemaker:CreatePresignedNotebookInstanceUrl",
            }
        ),
        target="any_role",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-sagemaker-presigned-url",
        name="SageMaker existing notebook URL (Rhino #28)",
        description="Create a presigned URL for an existing notebook and steal its execution role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"sagemaker:CreatePresignedNotebookInstanceUrl"}),
        target="execution_roles",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-codestar-passrole",
        name="CodeStar project PassRole (Rhino #24)",
        description="Create a CodeStar project that deploys resources under a passed privileged role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:PassRole", "codestar:CreateProject"}),
        target="any_role",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-codestar-template",
        name="CodeStar CreateProjectFromTemplate (Rhino #23)",
        description="Undocumented template API that can provision elevated CloudFormation resources.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"codestar:CreateProjectFromTemplate"}),
        target="admin_outcome",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-lambda-passrole-event-source",
        name="Lambda PassRole + event source mapping (Rhino #17)",
        description="Create a privileged Lambda and trigger it via DynamoDB event source without InvokeFunction.",
        provider=CloudProvider.AWS,
        required_actions=frozenset(
            {"iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"}
        ),
        target="any_role",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-lambda-passrole-add-permission",
        name="Lambda PassRole + AddPermission (Rhino #16)",
        description="Create a privileged Lambda and grant cross-account invoke via resource policy.",
        provider=CloudProvider.AWS,
        required_actions=frozenset(
            {"iam:PassRole", "lambda:CreateFunction", "lambda:AddPermission"}
        ),
        target="any_role",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-lambda-update-configuration-layer",
        name="Lambda malicious layer (Rhino #26)",
        description="Attach a malicious layer via UpdateFunctionConfiguration to hijack the function role.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"lambda:UpdateFunctionConfiguration"}),
        target="execution_roles",
        source="rhino-aws-privesc",
    ),
    AttackPattern(
        id="aws-iam-update-assume-role-and-sts",
        name="UpdateAssumeRolePolicy + AssumeRole (Rhino #14)",
        description="Rewrite a privileged role's trust policy to self, then sts:AssumeRole into it.",
        provider=CloudProvider.AWS,
        required_actions=frozenset({"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"}),
        target="any_role",
        source="rhino-aws-privesc",
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
    AttackPattern(
        id="gcp-sa-set-iam-policy",
        name="Service account IAM policy write",
        description="Grant the attacker service-account impersonation or key-management access.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.serviceAccounts.setIamPolicy"}),
        target="any_role",
    ),
    AttackPattern(
        id="gcp-sa-actas-create-run",
        name="Cloud Run + actAs",
        description="Deploy or update Cloud Run as a more privileged service account.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.serviceAccounts.actAs", "gcp:run.services.create"}),
        target="execution_roles",
    ),
    AttackPattern(
        id="gcp-sa-actas-create-gce",
        name="GCE + actAs",
        description="Create a VM with a privileged service account and retrieve its credentials.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.serviceAccounts.actAs", "gcp:compute.instances.create"}),
        target="execution_roles",
    ),
    AttackPattern(
        id="gcp-cloud-build-create",
        name="Cloud Build execution",
        description="Create a build that executes under the project Cloud Build service account.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:cloudbuild.builds.create"}),
        target="execution_roles",
    ),
    AttackPattern(
        id="gcp-deployment-manager",
        name="Deployment Manager deployment",
        description="Deploy resources or service accounts through Deployment Manager.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:deploymentmanager.deployments.create"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="gcp-roles-update",
        name="Custom role modification",
        description="Add privileged permissions to a custom IAM role assigned to the attacker.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.roles.update"}),
        target="admin_outcome",
    ),
    AttackPattern(
        id="gcp-sign-blob-jwt",
        name="Service account signing",
        description="Sign blobs or JWTs as another service account for token forgery workflows.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.serviceAccounts.signJwt"}),
        target="any_role",
    ),
    AttackPattern(
        id="gcp-implicit-delegation",
        name="Service account implicit delegation",
        description="Delegate chained service-account impersonation to reach a privileged identity.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:iam.serviceAccounts.implicitDelegation"}),
        target="any_role",
    ),
    AttackPattern(
        id="gcp-gce-set-metadata",
        name="GCE metadata manipulation",
        description="Replace startup scripts or SSH metadata on an instance to steal its service account token.",
        provider=CloudProvider.GCP,
        required_actions=frozenset({"gcp:compute.instances.setMetadata"}),
        target="execution_roles",
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
