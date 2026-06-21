from __future__ import annotations

from typing import Any

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot

ACCOUNT = "111111111111"
REGION = "us-east-1"


def _identity(
    builder: GraphBuilder,
    native_id: str,
    *,
    kind: str = "Role",
    display_name: str = "",
    **props: Any,
) -> str:
    merged = {"native_kind": kind, "arn": native_id if native_id.startswith("arn:") else None, **props}
    if display_name:
        merged["display_name"] = display_name
    merged = {k: v for k, v in merged.items() if v is not None}
    return builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id=native_id,
        props=merged,
    )


def _resource(
    builder: GraphBuilder,
    concept: ConceptType,
    native_id: str,
    resource_type: str,
    **props: Any,
) -> str:
    return builder.add_concept_node(
        concept_type=concept,
        native_id=native_id,
        props={"resource_type": resource_type, **props},
    )


def build_sample_enterprise_graph(session_id: str = "sample-enterprise") -> GraphSnapshot:
    """
    Dense offline corp graph for path-quality assessment.

    Three major storylines (multiple hops to high-value targets):
      1) Marketing/Sales — S3 + overpermissioned Lambda
      2) Engineering/Dev — CI/CD → EKS secrets write → pod/IRSA → vault bucket
      3) EC2 metadata — marketing instance → CI/CD → build runner → STS chain → admin
    """
    builder = GraphBuilder(session_id)

    # --- Org scope ---
    corp = builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id=f"aws:account:{ACCOUNT}",
        props={"display_name": "Corp production account", "provider": "aws"},
    )
    ou_marketing = builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id="aws:ou:marketing-sales",
        props={"display_name": "Marketing / Sales OU", "provider": "aws"},
    )
    ou_engineering = builder.add_concept_node(
        concept_type=ConceptType.SCOPE_BOUNDARY,
        native_id="aws:ou:engineering",
        props={"display_name": "Engineering OU", "provider": "aws"},
    )
    builder.add_edge(src_id=ou_marketing, rel_type="HOSTED_IN", dst_id=corp, props={"confidence": "explicit"})
    builder.add_edge(src_id=ou_engineering, rel_type="HOSTED_IN", dst_id=corp, props={"confidence": "explicit"})

    # --- Marketing / sales storyline ---
    marketing_analyst = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:user/marketing-analyst",
        kind="User",
        display_name="marketing-analyst",
        ou="marketing-sales",
    )
    marketing_lambda_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/marketing-lambda-exec",
        display_name="marketing-lambda-exec",
        ou="marketing-sales",
    )
    campaign_lambda = _resource(
        builder,
        ConceptType.RUNTIME_BINDING,
        f"LambdaFunction:arn:aws:lambda:{REGION}:{ACCOUNT}:function:campaign-sync",
        "LambdaFunction",
        function_name="campaign-sync",
        ou="marketing-sales",
    )
    marketing_assets = _resource(
        builder,
        ConceptType.DATA_STORE,
        "S3Bucket:marketing-assets",
        "S3Bucket",
        bucket_name="marketing-assets",
        ou="marketing-sales",
    )
    sales_leads = _resource(
        builder,
        ConceptType.DATA_STORE,
        "S3Bucket:sales-leads-export",
        "S3Bucket",
        bucket_name="sales-leads-export",
        ou="marketing-sales",
    )
    sales_secret = _resource(
        builder,
        ConceptType.SECRET_STORE,
        f"Secret:arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:sales/hubspot-token",
        "Secret",
        name="sales/hubspot-token",
        ou="marketing-sales",
    )
    decoy_marketing_bucket = _resource(
        builder,
        ConceptType.DATA_STORE,
        "S3Bucket:marketing-creative-archive",
        "S3Bucket",
        bucket_name="marketing-creative-archive",
        ou="marketing-sales",
    )

    builder.add_edge(
        src_id=marketing_analyst,
        rel_type="CONTROLS",
        dst_id=campaign_lambda,
        props={"action": "lambda:UpdateFunctionCode", "confidence": "explicit"},
    )
    builder.add_edge(
        src_id=campaign_lambda,
        rel_type="EXECUTES_AS",
        dst_id=marketing_lambda_role,
        props={"confidence": "explicit", "execution_role_arn": f"arn:aws:iam::{ACCOUNT}:role/marketing-lambda-exec"},
    )
    builder.add_edge(src_id=marketing_lambda_role, rel_type="READS", dst_id=marketing_assets, props={"confidence": "explicit"})
    builder.add_edge(src_id=marketing_lambda_role, rel_type="READS", dst_id=sales_leads, props={"confidence": "explicit"})
    builder.add_edge(src_id=marketing_lambda_role, rel_type="READS", dst_id=sales_secret, props={"confidence": "explicit"})
    builder.add_edge(src_id=marketing_analyst, rel_type="READS", dst_id=decoy_marketing_bucket, props={"confidence": "explicit"})

    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="policy:marketing-lambda-passrole",
        props={
            "principal_arn": f"arn:aws:iam::{ACCOUNT}:user/marketing-analyst",
            "actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        },
    )

    # --- EC2 metadata → CI/CD → second instance (default entry) ---
    marketing_ec2 = _resource(
        builder,
        ConceptType.RUNTIME_BINDING,
        f"EC2Instance:arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-marketing-web",
        "EC2Instance",
        instance_id="i-marketing-web",
        ou="marketing-sales",
        is_scenario_start=True,
        display_name="marketing-web (IMDS)",
    )
    marketing_web_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/marketing-web-instance",
        display_name="marketing-web-instance",
        ou="marketing-sales",
    )
    codepipeline = _resource(
        builder,
        ConceptType.MANAGEMENT_ENDPOINT,
        f"CodePipeline:arn:aws:codepipeline:{REGION}:{ACCOUNT}:corp-deploy-pipeline",
        "CodePipeline",
        pipeline_name="corp-deploy-pipeline",
        ou="platform",
    )
    pipeline_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/codepipeline-deploy",
        display_name="codepipeline-deploy",
        ou="platform",
    )
    cicd_ec2 = _resource(
        builder,
        ConceptType.RUNTIME_BINDING,
        f"EC2Instance:arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-cicd-build-runner",
        "EC2Instance",
        instance_id="i-cicd-build-runner",
        ou="platform",
        display_name="cicd-build-runner (IMDS)",
    )
    cicd_runner_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/cicd-build-runner-instance",
        display_name="cicd-build-runner-instance",
        ou="platform",
    )
    stray_audit_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/stray-security-audit",
        display_name="stray-security-audit",
        ou="legacy",
        notes="Orphaned read-only role with unexpected sts:AssumeRole grants",
    )
    engineering_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/engineering-poweruser",
        display_name="engineering-poweruser",
        ou="engineering",
    )
    org_admin_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/organization-admin",
        display_name="organization-admin",
        ou="corp",
    )
    prod_secret = _resource(
        builder,
        ConceptType.SECRET_STORE,
        f"Secret:arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:prod/platform-master",
        "Secret",
        name="prod/platform-master",
    )
    corp_vault_bucket = _resource(
        builder,
        ConceptType.DATA_STORE,
        "S3Bucket:corp-secret-vault",
        "S3Bucket",
        bucket_name="corp-secret-vault",
        ou="engineering",
    )

    builder.add_edge(
        src_id=marketing_ec2,
        rel_type="EXECUTES_AS",
        dst_id=marketing_web_role,
        props={"confidence": "explicit", "source": "instance-profile"},
    )
    builder.add_edge(
        src_id=marketing_web_role,
        rel_type="CONTROLS",
        dst_id=codepipeline,
        props={"action": "codepipeline:StartPipelineExecution", "confidence": "explicit"},
    )
    builder.add_edge(
        src_id=marketing_web_role,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=pipeline_role,
        props={"confidence": "explicit", "via": "pipeline-start-passrole"},
    )
    builder.add_edge(
        src_id=pipeline_role,
        rel_type="CONTROLS",
        dst_id=cicd_ec2,
        props={"action": "ssm:StartSession", "confidence": "explicit"},
    )
    builder.add_edge(
        src_id=cicd_ec2,
        rel_type="EXECUTES_AS",
        dst_id=cicd_runner_role,
        props={"confidence": "explicit", "source": "instance-profile"},
    )
    builder.add_edge(
        src_id=cicd_runner_role,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=stray_audit_role,
        props={"confidence": "explicit"},
    )
    builder.add_edge(
        src_id=stray_audit_role,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=engineering_role,
        props={"confidence": "explicit"},
    )
    builder.add_edge(
        src_id=engineering_role,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=org_admin_role,
        props={"confidence": "explicit"},
    )
    builder.add_edge(src_id=org_admin_role, rel_type="READS", dst_id=prod_secret, props={"confidence": "explicit"})
    builder.add_edge(src_id=org_admin_role, rel_type="READS", dst_id=corp_vault_bucket, props={"confidence": "explicit"})

    # --- Engineering / EKS / CI storyline ---
    dev_ci_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/CIDeployEngineering",
        display_name="CIDeployEngineering",
        ou="engineering",
    )
    eks_access_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/engineering-eks-access",
        display_name="engineering-eks-access",
        ou="engineering",
    )
    eks_irsa_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/eks-irsa-vault-reader",
        display_name="eks-irsa-vault-reader",
        ou="engineering",
    )
    eks_cluster = _resource(
        builder,
        ConceptType.ORCHESTRATION_SCOPE,
        f"EKSCluster:arn:aws:eks:{REGION}:{ACCOUNT}:cluster/corp-dev-eks",
        "EKSCluster",
        cluster_name="corp-dev-eks",
        ou="engineering",
    )
    eks_api = _resource(
        builder,
        ConceptType.MANAGEMENT_ENDPOINT,
        f"EKSApi:arn:aws:eks:{REGION}:{ACCOUNT}:cluster/corp-dev-eks",
        "EKSCluster",
        cluster_name="corp-dev-eks",
        ou="engineering",
    )
    secrets_writer_sa = _identity(
        builder,
        "kubernetes:serviceaccount:platform:secrets-writer",
        kind="ServiceAccount",
        display_name="platform/secrets-writer",
        namespace="platform",
        provider="kubernetes",
    )
    harvest_pod = _resource(
        builder,
        ConceptType.WORKLOAD,
        "kubernetes:pod:platform:secret-harvest",
        "Pod",
        namespace="platform",
        name="secret-harvest",
        service_account="secrets-writer",
        ou="engineering",
    )
    vault_bootstrap_secret = _resource(
        builder,
        ConceptType.SECRET_STORE,
        "kubernetes:secret:platform:vault-bootstrap-token",
        "KubernetesSecret",
        namespace="platform",
        name="vault-bootstrap-token",
    )
    ci_worker_lambda = _resource(
        builder,
        ConceptType.RUNTIME_BINDING,
        f"LambdaFunction:arn:aws:lambda:{REGION}:{ACCOUNT}:function:ci-worker",
        "LambdaFunction",
        function_name="ci-worker",
        ou="engineering",
    )

    builder.add_edge(
        src_id=dev_ci_role,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=eks_access_role,
        props={"confidence": "explicit"},
    )
    builder.add_edge(
        src_id=eks_access_role,
        rel_type="CAN_ACCESS",
        dst_id=eks_api,
        props={"action": "eks:AccessKubernetesApi", "confidence": "explicit"},
    )
    builder.add_edge(
        src_id=eks_access_role,
        rel_type="CONTROLS",
        dst_id=harvest_pod,
        props={"action": "rbac:pods:create", "confidence": "explicit", "namespace": "platform"},
    )
    builder.add_edge(
        src_id=harvest_pod,
        rel_type="EXECUTES_AS",
        dst_id=secrets_writer_sa,
        props={"confidence": "explicit"},
    )
    builder.add_edge(
        src_id=secrets_writer_sa,
        rel_type="READS",
        dst_id=vault_bootstrap_secret,
        props={"confidence": "explicit", "rbac_rule": {"verbs": ["get", "list"], "resources": ["secrets"]}},
    )
    builder.add_edge(
        src_id=secrets_writer_sa,
        rel_type="PROJECTS_TO",
        dst_id=eks_irsa_role,
        props={"binding_type": "IRSA", "confidence": "explicit"},
    )
    builder.add_edge(src_id=eks_irsa_role, rel_type="READS", dst_id=corp_vault_bucket, props={"confidence": "explicit"})
    builder.add_edge(
        src_id=engineering_role,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=eks_access_role,
        props={"confidence": "explicit", "notes": "Shared engineering access from STS chain"},
    )
    builder.add_edge(
        src_id=engineering_role,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=dev_ci_role,
        props={"confidence": "explicit"},
    )
    builder.add_edge(
        src_id=dev_ci_role,
        rel_type="CONTROLS",
        dst_id=ci_worker_lambda,
        props={"action": "lambda:UpdateFunctionCode", "confidence": "explicit"},
    )
    builder.add_edge(
        src_id=ci_worker_lambda,
        rel_type="EXECUTES_AS",
        dst_id=dev_ci_role,
        props={"confidence": "explicit"},
    )
    builder.add_edge(
        src_id=eks_cluster,
        rel_type="HOSTED_IN",
        dst_id=ou_engineering,
        props={"confidence": "explicit"},
    )

    # --- Decoys / noise ---
    decoy_role = _identity(
        builder,
        f"arn:aws:iam::{ACCOUNT}:role/readonly-auditor",
        display_name="readonly-auditor",
        ou="security",
    )
    decoy_bucket = _resource(
        builder,
        ConceptType.DATA_STORE,
        "S3Bucket:public-website-static",
        "S3Bucket",
        bucket_name="public-website-static",
    )
    builder.add_edge(src_id=decoy_role, rel_type="READS", dst_id=decoy_bucket, props={"confidence": "explicit"})
    builder.add_edge(
        src_id=marketing_web_role,
        rel_type="READS",
        dst_id=decoy_bucket,
        props={"confidence": "explicit", "decoy": True},
    )

    builder.add_concept_node(
        concept_type=ConceptType.ENTITLEMENT,
        native_id="policy:ci-deploy-lambda-privesc",
        props={
            "principal_arn": f"arn:aws:iam::{ACCOUNT}:role/CIDeployEngineering",
            "actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        },
    )

    all_nodes = [
        corp,
        ou_marketing,
        ou_engineering,
        marketing_analyst,
        marketing_lambda_role,
        campaign_lambda,
        marketing_assets,
        sales_leads,
        sales_secret,
        marketing_ec2,
        marketing_web_role,
        codepipeline,
        pipeline_role,
        cicd_ec2,
        cicd_runner_role,
        stray_audit_role,
        engineering_role,
        org_admin_role,
        prod_secret,
        corp_vault_bucket,
        dev_ci_role,
        eks_access_role,
        eks_irsa_role,
        eks_cluster,
        eks_api,
        secrets_writer_sa,
        harvest_pod,
        vault_bootstrap_secret,
        ci_worker_lambda,
        decoy_role,
        decoy_bucket,
        decoy_marketing_bucket,
    ]
    for node_id in all_nodes:
        builder.link_session(node_id)

    apply_attack_analysis(
        builder,
        provider=CloudProvider.AWS,
        start_node_ids=[
            marketing_analyst,
            marketing_web_role,
            cicd_runner_role,
            dev_ci_role,
            engineering_role,
        ],
    )
    return builder.snapshot


def load_sample_enterprise_session_metadata() -> dict[str, Any]:
    return {
        "caller_arn": f"EC2Instance:arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-marketing-web",
        "scope_id": f"aws:account:{ACCOUNT}",
        "provider": "aws",
        "artifact_count": 0,
        "node_count": 35,
        "sample": True,
        "scenario": "enterprise-mock",
        "environment": "corp-mock",
        "storylines": ["marketing-lambda", "ec2-metadata-sts-chain", "engineering-eks-vault"],
    }
