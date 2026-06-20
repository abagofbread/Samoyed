from __future__ import annotations

from typing import Any

from samoyed.attack.analyzer import apply_attack_analysis
from samoyed.attack.host_pivot import HostCredentialStore, HostInteractiveSession, HostPivotSpec, apply_host_pivot
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.model import GraphSnapshot


def build_sample_host_graph(session_id: str = "sample-host") -> GraphSnapshot:
    """
    Developer laptop compromised → cached AWS SSO + Entra ID session → cloud blast radius.
    Paths:
      - workstation LOGGED_IN_AS azure user → Contributor → storage
      - workstation STORES_CREDS_FOR aws dev user → assume admin role → secret
      - dev lambda EXECUTES_AS admin role (pivot if UpdateFunctionCode)
    """
    builder = GraphBuilder(session_id)

    dev_user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:user/dev-bob",
        props={"native_kind": "User", "arn": "arn:aws:iam::111111111111:user/dev-bob", "display_name": "dev-bob"},
    )
    admin_role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::111111111111:role/admin",
        props={"native_kind": "Role", "arn": "arn:aws:iam::111111111111:role/admin"},
    )
    azure_user = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="azure:user:bob@corp.com",
        props={"native_kind": "User", "display_name": "bob@corp.com", "provider": "azure"},
    )
    secret = builder.add_concept_node(
        concept_type=ConceptType.SECRET_STORE,
        native_id="Secret:arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db",
        props={"resource_type": "Secret", "name": "prod-db"},
    )
    bucket = builder.add_concept_node(
        concept_type=ConceptType.DATA_STORE,
        native_id="StorageAccount:corpdata",
        props={"resource_type": "StorageAccount", "account_name": "corpdata", "provider": "azure"},
    )
    lambda_fn = builder.add_concept_node(
        concept_type=ConceptType.RUNTIME_BINDING,
        native_id="LambdaFunction:arn:aws:lambda:us-east-1:111111111111:function:internal-tool",
        props={
            "resource_type": "LambdaFunction",
            "function_name": "internal-tool",
            "arn": "arn:aws:lambda:us-east-1:111111111111:function:internal-tool",
        },
    )

    apply_host_pivot(
        builder,
        HostPivotSpec(
            host_native_id="host:workstation:bob-laptop",
            display_name="Bob's developer laptop",
            interactive_sessions=[
                HostInteractiveSession(
                    identity_native_id="azure:user:bob@corp.com",
                    session_type="interactive",
                    provider=CloudProvider.AZURE,
                    notes="Entra ID PRT / SSO session in browser + OS token cache",
                ),
            ],
            credential_stores=[
                HostCredentialStore(
                    identity_native_id="arn:aws:iam::111111111111:user/dev-bob",
                    store_type="aws-sso-cache",
                    path_hint="~/.aws/sso/cache/*.json",
                    provider=CloudProvider.AWS,
                ),
            ],
        ),
    )

    builder.add_edge(
        src_id=dev_user,
        rel_type="CAN_ASSUME_ROLE",
        dst_id=admin_role,
        props={"confidence": "explicit"},
    )
    builder.add_edge(src_id=admin_role, rel_type="READS", dst_id=secret, props={"confidence": "explicit"})
    builder.add_edge(
        src_id=azure_user,
        rel_type="READS",
        dst_id=bucket,
        props={"confidence": "explicit", "role": "Storage Blob Data Contributor"},
    )
    builder.add_edge(
        src_id=dev_user,
        rel_type="CONTROLS",
        dst_id=lambda_fn,
        props={"action": "lambda:UpdateFunctionCode", "confidence": "explicit"},
    )
    builder.add_edge(
        src_id=lambda_fn,
        rel_type="EXECUTES_AS",
        dst_id=admin_role,
        props={"confidence": "explicit", "execution_role_arn": "arn:aws:iam::111111111111:role/admin"},
    )

    for node_id in (dev_user, admin_role, azure_user, secret, bucket, lambda_fn):
        builder.link_session(node_id)

    apply_attack_analysis(builder, provider=CloudProvider.AWS)
    return builder.snapshot


def load_sample_host_session_metadata() -> dict[str, Any]:
    return {
        "caller_arn": "host:workstation:bob-laptop",
        "scope_id": "host:corp:engineering",
        "provider": "aws",
        "artifact_count": 0,
        "node_count": 8,
        "sample": True,
        "scenario": "host-compromise",
    }
