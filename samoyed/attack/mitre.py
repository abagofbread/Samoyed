"""
MITRE ATT&CK Enterprise mappings for cloud / IaaS attack-path edges.

References:
- https://attack.mitre.org/matrices/enterprise/cloud/
- IaaS platform techniques (AWS, Azure, GCP shared tactics)

Used to annotate graph edges with technique IDs for enrichment and reporting.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ATTACK_BASE = "https://attack.mitre.org/techniques"


@dataclass(frozen=True)
class MitreTechnique:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        if "." in self.id:
            parent, sub = self.id.split(".", 1)
            return f"{ATTACK_BASE}/{parent}/{sub}/"
        return f"{ATTACK_BASE}/{self.id}/"


# Curated IaaS-relevant techniques (Enterprise matrix, cloud platforms).
TECHNIQUES: dict[str, MitreTechnique] = {
    "T1078.004": MitreTechnique("T1078.004", "Valid Accounts: Cloud Accounts", "defense-evasion"),
    "T1098": MitreTechnique("T1098", "Account Manipulation", "persistence"),
    "T1098.001": MitreTechnique("T1098.001", "Additional Cloud Credentials", "persistence"),
    "T1098.003": MitreTechnique("T1098.003", "Additional Cloud Roles", "persistence"),
    "T1550.001": MitreTechnique("T1550.001", "Application Access Token", "defense-evasion"),
    "T1552": MitreTechnique("T1552", "Unsecured Credentials", "credential-access"),
    "T1552.001": MitreTechnique("T1552.001", "Credentials In Files", "credential-access"),
    "T1552.005": MitreTechnique("T1552.005", "Cloud Instance Metadata API", "credential-access"),
    "T1552.007": MitreTechnique("T1552.007", "Container API", "credential-access"),
    "T1530": MitreTechnique("T1530", "Data from Cloud Storage", "collection"),
    "T1526": MitreTechnique("T1526", "Cloud Service Discovery", "discovery"),
    "T1580": MitreTechnique("T1580", "Cloud Infrastructure Discovery", "discovery"),
    "T1578": MitreTechnique("T1578", "Modify Cloud Compute Infrastructure", "defense-evasion"),
    "T1578.001": MitreTechnique("T1578.001", "Create Snapshot", "defense-evasion"),
    "T1578.002": MitreTechnique("T1578.002", "Create Cloud Instance", "defense-evasion"),
    "T1578.005": MitreTechnique("T1578.005", "Modify Cloud Compute Configurations", "defense-evasion"),
    "T1059.009": MitreTechnique("T1059.009", "Cloud API", "execution"),
    "T1021.008": MitreTechnique("T1021.008", "Direct Cloud VM Connections", "lateral-movement"),
    "T1609": MitreTechnique("T1609", "Container Administration Command", "execution"),
    "T1611": MitreTechnique("T1611", "Escape to Host", "privilege-escalation"),
    "T1548": MitreTechnique("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1562.008": MitreTechnique("T1562.008", "Disable Cloud Logs", "defense-evasion"),
    "T1485": MitreTechnique("T1485", "Data Destruction", "impact"),
    "T1537": MitreTechnique("T1537", "Transfer Data to Cloud Account", "exfiltration"),
}

# Samoyed attack-pattern id → MITRE technique ids
PATTERN_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "aws-iam-attach-user-policy": ("T1098.003", "T1098"),
    "aws-iam-put-user-policy": ("T1098.001", "T1098"),
    "aws-iam-attach-role-policy": ("T1098.003", "T1098"),
    "aws-iam-put-role-policy": ("T1098.003", "T1098"),
    "aws-iam-create-access-key": ("T1098.001", "T1098"),
    "aws-iam-create-login-profile": ("T1098.001", "T1098"),
    "aws-iam-update-login-profile": ("T1098.001", "T1098"),
    "aws-iam-create-policy-version": ("T1098.003", "T1098"),
    "aws-iam-set-default-policy-version": ("T1098.003", "T1098"),
    "aws-iam-add-user-to-group": ("T1098.003", "T1098"),
    "aws-iam-update-assume-role-policy": ("T1098.003", "T1548"),
    "aws-lambda-create-invoke": ("T1578.002", "T1059.009"),
    "aws-lambda-create-invoke-url": ("T1578.002", "T1059.009"),
    "aws-lambda-update-code": ("T1578.005", "T1059.009"),
    "aws-lambda-add-permission": ("T1578.005", "T1098.003"),
    "aws-cloudformation-create-stack": ("T1578.002", "T1059.009"),
    "aws-ec2-run-instances": ("T1578.002", "T1552.005"),
    "aws-ec2-create-snapshot": ("T1578.001",),
    "aws-ec2-modify-instance-attribute": ("T1578.005",),
    "aws-ssm-send-command": ("T1021.008", "T1059.009"),
    "aws-ecs-run-task": ("T1578.002", "T1059.009"),
    "aws-states-test-state": ("T1059.009", "T1578.002"),
    "aws-disable-cloudtrail": ("T1562.008",),
    "gcp-sa-actas-create-function": ("T1578.002", "T1098.003"),
    "gcp-sa-actas-deploy": ("T1578.002", "T1098.003"),
    "gcp-sa-key-create": ("T1098.001",),
    "gcp-set-iam-policy": ("T1098.003", "T1098"),
    "gcp-token-creator": ("T1098.001", "T1550.001"),
    "azure-role-assignment-write": ("T1098.003", "T1098"),
    "azure-uami-assign": ("T1578.005", "T1552.005"),
    "azure-run-command": ("T1021.008", "T1059.009"),
    "azure-keyvault-access-policy": ("T1098.003",),
    "host-interactive-session": ("T1550.001", "T1552"),
    "host-credential-store": ("T1552.001", "T1552"),
    "k8s-cluster-admin-binding": ("T1078.004", "T1548"),
    "k8s-secrets-write": ("T1552.007", "T1098.001"),
    "k8s-pods-exec": ("T1609", "T1552.007"),
}

# IAM / API action substring → techniques (for CONTROLS / probe edges)
ACTION_TECHNIQUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("iam:AttachUserPolicy", ("T1098.003",)),
    ("iam:PutUserPolicy", ("T1098.001",)),
    ("iam:AttachRolePolicy", ("T1098.003",)),
    ("iam:PutRolePolicy", ("T1098.003",)),
    ("iam:CreateAccessKey", ("T1098.001",)),
    ("iam:CreateLoginProfile", ("T1098.001",)),
    ("iam:UpdateLoginProfile", ("T1098.001",)),
    ("iam:CreatePolicyVersion", ("T1098.003",)),
    ("iam:SetDefaultPolicyVersion", ("T1098.003",)),
    ("iam:AddUserToGroup", ("T1098.003",)),
    ("iam:UpdateAssumeRolePolicy", ("T1098.003", "T1548")),
    ("iam:PassRole", ("T1098.003", "T1548")),
    ("lambda:UpdateFunctionCode", ("T1578.005", "T1059.009")),
    ("lambda:CreateFunction", ("T1578.002", "T1059.009")),
    ("lambda:InvokeFunction", ("T1059.009",)),
    ("lambda:AddPermission", ("T1098.003",)),
    ("cloudformation:CreateStack", ("T1578.002",)),
    ("ec2:RunInstances", ("T1578.002", "T1552.005")),
    ("ec2:CreateSnapshot", ("T1578.001",)),
    ("ec2:ModifyInstanceAttribute", ("T1578.005",)),
    ("ssm:SendCommand", ("T1021.008", "T1059.009")),
    ("ssm:StartSession", ("T1021.008",)),
    ("ecs:RunTask", ("T1578.002",)),
    ("states:TestState", ("T1059.009",)),
    ("cloudtrail:StopLogging", ("T1562.008",)),
    ("cloudtrail:DeleteTrail", ("T1562.008",)),
    ("s3:GetObject", ("T1530",)),
    ("s3:ListBucket", ("T1526", "T1530")),
    ("secretsmanager:GetSecretValue", ("T1552", "T1530")),
    ("ssm:GetParameter", ("T1552",)),
    ("sts:AssumeRole", ("T1078.004", "T1548")),
    ("eks:DescribeCluster", ("T1580", "T1526")),
    ("codepipeline:StartPipelineExecution", ("T1059.009",)),
    ("host:interactive-session", ("T1550.001",)),
    ("host:credential-store", ("T1552.001",)),
    ("rbac:cluster-admin", ("T1078.004", "T1548")),
    ("rbac:pods:exec", ("T1609",)),
    ("rbac:secrets:write", ("T1552.007",)),
)

# Structural relationship → techniques
RELATIONSHIP_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "CAN_ASSUME_ROLE": ("T1078.004", "T1548"),
    "EXECUTES_AS": ("T1552.005", "T1078.004"),
    "PROJECTS_TO": ("T1552.005", "T1078.004"),
    "READS": ("T1530",),
    "WRITES": ("T1485", "T1578"),
    "DELETES": ("T1485",),
    "CONTROLS": ("T1059.009",),
    "CAN_ACCESS": ("T1526", "T1580"),
    "CAN_PRIVESC_TO": ("T1548",),
    "LOGGED_IN_AS": ("T1078.004", "T1550.001"),
    "STORES_CREDS_FOR": ("T1552.001",),
    "CAN_STEAL_CREDS_FROM": ("T1552.001", "T1550.001"),
    "HAS_ESCAPE_SURFACE": ("T1611",),
    "CAN_ESCAPE_TO": ("T1611", "T1552.005"),
    "RUNS_ON": ("T1610",),
    "DEPENDS_ON": ("T1578",),
    "FEEDS": ("T1578", "T1609", "T1525"),
}


def techniques_for_action(action: str) -> list[MitreTechnique]:
    action = (action or "").strip()
    if not action:
        return []
    found: list[str] = []
    for prefix, tids in ACTION_TECHNIQUES:
        if prefix in action or action == prefix:
            found.extend(tids)
    return _dedupe_techniques(found)


def techniques_for_relationship(rel_type: str, props: dict[str, Any] | None = None) -> list[MitreTechnique]:
    props = props or {}
    tids = list(RELATIONSHIP_TECHNIQUES.get(rel_type, ()))
    if rel_type == "READS":
        rtype = str(props.get("resource_type") or props.get("target_concept") or "")
        if rtype in {"Secret", "KubernetesSecret", "GCPSecret"} or "Secret" in rtype:
            tids = list(tids) + ["T1552", "T1552.007"]
    if rel_type == "CONTROLS" and props.get("action"):
        tids = list(tids) + [t.id for t in techniques_for_action(str(props["action"]))]
    if rel_type == "EXECUTES_AS":
        rtype = str(props.get("resource_type") or "")
        if rtype == "LambdaFunction":
            tids = list(tids) + ["T1578.005"]
    return _dedupe_techniques(tids)


def techniques_for_pattern(pattern_id: str) -> list[MitreTechnique]:
    return _dedupe_techniques(list(PATTERN_TECHNIQUES.get(pattern_id, ())))


def _dedupe_techniques(tids: list[str]) -> list[MitreTechnique]:
    out: list[MitreTechnique] = []
    seen: set[str] = set()
    for tid in tids:
        if tid in seen:
            continue
        tech = TECHNIQUES.get(tid)
        if tech:
            seen.add(tid)
            out.append(tech)
    return out


def mitre_props_for_edge(rel_type: str, props: dict[str, Any]) -> dict[str, Any]:
    """Build MITRE annotation fields to merge onto a graph edge."""
    techniques: list[MitreTechnique] = []
    pattern_id = props.get("pattern_id")
    if pattern_id:
        techniques.extend(techniques_for_pattern(str(pattern_id)))
    if props.get("action"):
        techniques.extend(techniques_for_action(str(props["action"])))
    techniques.extend(techniques_for_relationship(rel_type, props))
    if not techniques:
        return {}
    return _serialize_techniques(techniques)


def _serialize_techniques(techniques: list[MitreTechnique]) -> dict[str, Any]:
    # Dedupe again while preserving order
    seen: set[str] = set()
    unique: list[MitreTechnique] = []
    for t in techniques:
        if t.id not in seen:
            seen.add(t.id)
            unique.append(t)
    return {
        "mitre_technique_ids": [t.id for t in unique],
        "mitre_technique_names": [t.name for t in unique],
        "mitre_tactics": sorted({t.tactic for t in unique}),
        "mitre_urls": [t.url for t in unique],
        "mitre_framework": "ATT&CK Enterprise",
    }


def enrich_graph_edges(graph: Any) -> int:
    """Annotate all edges in a GraphSnapshot with MITRE metadata. Returns count enriched."""
    enriched = 0
    for edge in graph.edges:
        extra = mitre_props_for_edge(edge.rel_type, edge.props)
        if not extra:
            continue
        for key, value in extra.items():
            if edge.props.get(key) != value:
                edge.props[key] = value
                enriched += 1
    return enriched


def export_mitre_catalog() -> dict[str, Any]:
    return {
        "framework": "MITRE ATT&CK Enterprise",
        "matrix_url": "https://attack.mitre.org/matrices/enterprise/cloud/",
        "technique_count": len(TECHNIQUES),
        "techniques": [
            {"id": t.id, "name": t.name, "tactic": t.tactic, "url": t.url}
            for t in TECHNIQUES.values()
        ],
        "pattern_mappings": {
            pid: list(tids) for pid, tids in PATTERN_TECHNIQUES.items()
        },
        "relationship_mappings": {
            rel: list(tids) for rel, tids in RELATIONSHIP_TECHNIQUES.items()
        },
    }
