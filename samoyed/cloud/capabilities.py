from __future__ import annotations

import re
from dataclasses import dataclass

from .concepts import CapabilityType

# AWS IAM action prefix → capability + resource type hints
AWS_ACTION_MAP: list[tuple[re.Pattern[str], CapabilityType, str | None]] = [
    (re.compile(r"^s3:GetObject|^s3:List"), CapabilityType.READS, "S3Bucket"),
    (re.compile(r"^s3:PutObject|^s3:DeleteObject"), CapabilityType.WRITES, "S3Bucket"),
    (re.compile(r"^s3:\*"), CapabilityType.CONTROLS, "S3Bucket"),
    (re.compile(r"^secretsmanager:GetSecretValue|^secretsmanager:ListSecrets"), CapabilityType.READS, "Secret"),
    (re.compile(r"^secretsmanager:PutSecretValue|^secretsmanager:CreateSecret"), CapabilityType.WRITES, "Secret"),
    (re.compile(r"^secretsmanager:\*"), CapabilityType.CONTROLS, "Secret"),
    (re.compile(r"^ssm:GetParameter"), CapabilityType.READS, "SSMParameter"),
    (re.compile(r"^ssm:PutParameter"), CapabilityType.WRITES, "SSMParameter"),
    (re.compile(r"^kms:Decrypt|^kms:DescribeKey"), CapabilityType.READS, "KMSKey"),
    (re.compile(r"^kms:\*"), CapabilityType.CONTROLS, "KMSKey"),
    (re.compile(r"^iam:PassRole|^iam:CreateRole|^iam:AttachRolePolicy"), CapabilityType.CONTROLS, "Role"),
    (re.compile(r"^iam:AssumeRole"), CapabilityType.EXECUTES, "Role"),
    (re.compile(r"^sts:AssumeRole"), CapabilityType.EXECUTES, "Role"),
    (re.compile(r"^ec2:RunInstances|^ec2:StartInstances"), CapabilityType.EXECUTES, "EC2Instance"),
    (re.compile(r"^lambda:InvokeFunction"), CapabilityType.EXECUTES, "LambdaFunction"),
    (re.compile(r"^ecr:GetDownloadUrlForLayer|^ecr:BatchGetImage"), CapabilityType.READS, "ECRRepository"),
    (re.compile(r"^ecr:PutImage|^ecr:InitiateLayerUpload"), CapabilityType.WRITES, "ECRRepository"),
    (re.compile(r"^\*"), CapabilityType.CONTROLS, None),
]


@dataclass(frozen=True)
class ActionMapping:
    capability: CapabilityType
    resource_type: str | None


def map_aws_action(action: str) -> ActionMapping | None:
    action = action.strip()
    if action == "*":
        return ActionMapping(CapabilityType.CONTROLS, None)
    for pattern, cap, rtype in AWS_ACTION_MAP:
        if pattern.search(action):
            return ActionMapping(cap, rtype)
    # Generic read/write heuristics
    if ":Get" in action or ":List" in action or ":Describe" in action:
        return ActionMapping(CapabilityType.READS, _service_from_action(action))
    if ":Put" in action or ":Create" in action or ":Update" in action:
        return ActionMapping(CapabilityType.WRITES, _service_from_action(action))
    if ":Delete" in action:
        return ActionMapping(CapabilityType.DELETES, _service_from_action(action))
    return None


def _service_from_action(action: str) -> str | None:
    if ":" not in action:
        return None
    return action.split(":")[0].title()


# GCP predefined role → capability hints (resource_type for graph targets)
GCP_ROLE_MAP: dict[str, tuple[CapabilityType, str | None]] = {
    "roles/secretmanager.secretAccessor": (CapabilityType.READS, "GCPSecret"),
    "roles/secretmanager.admin": (CapabilityType.CONTROLS, "GCPSecret"),
    "roles/storage.objectViewer": (CapabilityType.READS, "GCSBucket"),
    "roles/storage.objectAdmin": (CapabilityType.WRITES, "GCSBucket"),
    "roles/storage.admin": (CapabilityType.CONTROLS, "GCSBucket"),
    "roles/iam.serviceAccountUser": (CapabilityType.EXECUTES, "ServiceAccount"),
    "roles/iam.serviceAccountTokenCreator": (CapabilityType.EXECUTES, "ServiceAccount"),
    "roles/owner": (CapabilityType.CONTROLS, None),
    "roles/editor": (CapabilityType.CONTROLS, None),
}


def map_gcp_role(role: str) -> ActionMapping | None:
    role = role.strip()
    if role in GCP_ROLE_MAP:
        cap, rtype = GCP_ROLE_MAP[role]
        return ActionMapping(cap, rtype)
    if "secretmanager" in role and "secret" in role:
        return ActionMapping(CapabilityType.READS, "GCPSecret")
    if "storage" in role:
        return ActionMapping(CapabilityType.READS, "GCSBucket")
    return None


def gcp_member_native_id(member: str) -> str:
    if member.startswith("serviceAccount:"):
        return f"gcp:serviceaccount:{member.split(':', 1)[1]}"
    if member.startswith("user:"):
        return f"gcp:user:{member.split(':', 1)[1]}"
    if member.startswith("group:"):
        return f"gcp:group:{member.split(':', 1)[1]}"
    return f"gcp:member:{member}"


# Azure built-in role name fragments → capability
AZURE_ROLE_MAP: list[tuple[str, CapabilityType, str | None]] = [
    ("Key Vault Secrets User", CapabilityType.READS, "KeyVaultSecret"),
    ("Key Vault Administrator", CapabilityType.CONTROLS, "KeyVaultSecret"),
    ("Storage Blob Data Reader", CapabilityType.READS, "StorageAccount"),
    ("Storage Blob Data Contributor", CapabilityType.WRITES, "StorageAccount"),
    ("Owner", CapabilityType.CONTROLS, None),
    ("Contributor", CapabilityType.CONTROLS, None),
    ("User Access Administrator", CapabilityType.CONTROLS, "Identity"),
]


def map_azure_role(role_name: str) -> ActionMapping | None:
    for fragment, cap, rtype in AZURE_ROLE_MAP:
        if fragment.lower() in role_name.lower():
            return ActionMapping(cap, rtype)
    return None


def gcp_role_to_actions(role: str) -> set[str]:
    role = role.strip()
    mapping: dict[str, set[str]] = {
        "roles/owner": {"gcp:owner", "gcp:resourcemanager.projects.setIamPolicy"},
        "roles/editor": {"gcp:editor"},
        "roles/iam.serviceAccountUser": {"gcp:iam.serviceAccounts.actAs"},
        "roles/iam.serviceAccountTokenCreator": {"gcp:iam.serviceAccounts.getAccessToken"},
        "roles/iam.serviceAccountKeyAdmin": {"gcp:iam.serviceAccountKeys.create"},
        "roles/cloudfunctions.developer": {"gcp:cloudfunctions.functions.create"},
        "roles/run.admin": {"gcp:run.services.create"},
    }
    if role in mapping:
        return set(mapping[role])
    out: set[str] = set()
    if "serviceAccountUser" in role or "serviceAccountAdmin" in role:
        out.add("gcp:iam.serviceAccounts.actAs")
    if "cloudfunctions" in role:
        out.add("gcp:cloudfunctions.functions.create")
    if role.endswith("/owner"):
        out.add("gcp:resourcemanager.projects.setIamPolicy")
    return out


def azure_role_to_actions(role_name: str) -> set[str]:
    name = role_name.lower()
    out: set[str] = set()
    if "owner" in name or "user access administrator" in name:
        out.add("azure:authorization.roleAssignments.write")
    if "contributor" in name:
        out.add("azure:authorization.roleAssignments.write")
    if "virtual machine contributor" in name:
        out.add("azure:compute.virtualMachines.write")
        out.add("azure:compute.virtualMachines.runCommand")
    if "key vault administrator" in name:
        out.add("azure:keyvault.vaults.write")
    if "managed identity operator" in name:
        out.add("azure:managedIdentity.userAssignedIdentities.assign")
    return out


def azure_principal_native_id(principal_type: str, principal_id: str, name: str | None = None) -> str:
    if name:
        return f"azure:{principal_type.lower()}:{name}"
    return f"azure:{principal_type.lower()}:{principal_id}"

