from __future__ import annotations

import json
from pathlib import Path

from samoyed.attack.analyzer import collect_principal_actions, has_required_actions
from samoyed.cloud.concepts import ConceptType
from samoyed.collectors.adapters import adapt_tool_report
from samoyed.collectors.detect import detect_collect_target, detect_repo_signals
from samoyed.collectors.dispatch import collect_target
from samoyed.collectors.on_host import collect_on_host
from samoyed.collectors.static import collect_static_source
from samoyed.connectors.aws_authz.importer import import_aws_authz_details
from samoyed.graph.builder import GraphBuilder
from samoyed.policy.boundary import actions_from_policy_document


def test_detect_repo_signals_terraform(tmp_path: Path):
    (tmp_path / "main.tf").write_text('resource "aws_iam_role" "r" {}', encoding="utf-8")
    signals = detect_repo_signals(tmp_path)
    assert "terraform" in signals


def test_detect_host_token():
    surface = detect_collect_target("host")
    assert surface.mode == "on-host"


def test_collect_static_unbound(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    report = collect_static_source(repo)
    assert report["bindings"][0]["target_ref"] == "unbound"
    assert report["bindings"][0].get("bind_required") is True


def test_collect_target_ingests_trufflehog(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("ok\n", encoding="utf-8")
    tool = tmp_path / "trufflehog.json"
    tool.write_text(
        json.dumps(
            [
                {
                    "DetectorName": "AWS",
                    "Verified": True,
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "app/.env", "line": 1}}},
                }
            ]
        ),
        encoding="utf-8",
    )
    report = collect_target(repo, ingest_reports=[tool])
    kinds = {m["kind"] for m in report["bindings"][0]["materials"]}
    assert "aws_access_key_env" in kinds
    assert report["collector"] == "consolidated"


def test_adapt_gitleaks_findings():
    materials = adapt_tool_report(
        [{"RuleID": "aws-access-key", "Description": "AWS Access Key", "File": "x.env", "StartLine": 2}],
        source_label="gitleaks.json",
    )
    assert materials[0]["kind"] == "aws_access_key_env"


def test_collect_on_host_none_or_env(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    report = collect_on_host(target_ref="EC2Instance:lab", include_environ=True)
    assert report["collector_mode"] == "on-host"
    kinds = {m["kind"] for m in report["bindings"][0]["materials"]}
    assert "aws_access_key_env" in kinds
    assert report["bindings"][0]["target_ref"] == "EC2Instance:lab"


def test_permissions_boundary_clamps_iam_star():
    builder = GraphBuilder("boundary-test")
    role = builder.add_concept_node(
        concept_type=ConceptType.IDENTITY,
        native_id="arn:aws:iam::1:role/bounded",
        props={
            "native_kind": "Role",
            "permissions_boundary_arn": "arn:aws:iam::1:policy/boundary",
            "permissions_boundary_actions": ["iam:PassRole", "ec2:RunInstances", "ec2:Describe*"],
        },
    )
    builder.add_edge(
        src_id=role,
        rel_type="CONTROLS",
        dst_id=builder.add_concept_node(
            concept_type=ConceptType.IDENTITY,
            native_id="IAM:*",
            props={"native_kind": "IAM"},
        ),
        props={"action": "iam:*", "policy": "IAMFullAccess"},
    )
    actions = collect_principal_actions(builder.snapshot, role)
    assert "iam:PassRole" in actions
    assert not has_required_actions(actions, frozenset({"iam:AttachRolePolicy"}))
    assert has_required_actions(actions, frozenset({"iam:PassRole"}))


def test_authz_import_permissions_boundary():
    payload = {
        "account_id": "111111111111",
        "UserDetailList": [],
        "RoleDetailList": [
            {
                "Arn": "arn:aws:iam::111111111111:role/bounded",
                "RoleName": "bounded",
                "PermissionsBoundary": {
                    "PermissionsBoundaryArn": "arn:aws:iam::111111111111:policy/bound",
                    "PermissionsBoundaryType": "Policy",
                },
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "AttachedManagedPolicies": [],
                "RolePolicyList": [
                    {
                        "PolicyName": "full-iam",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:*",
                                    "Resource": "arn:aws:iam::111111111111:role/admin",
                                }
                            ],
                        },
                    }
                ],
            }
        ],
        "Policies": [
            {
                "Arn": "arn:aws:iam::111111111111:policy/bound",
                "PolicyName": "bound",
                "PolicyVersionList": [
                    {
                        "IsDefaultVersion": True,
                        "Document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["iam:PassRole", "ec2:RunInstances"],
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                ],
            },
        ],
    }
    builder, _meta = import_aws_authz_details(json.dumps(payload), session_id="pb-authz")
    node_id = next(nid for nid, n in builder.snapshot.nodes.items() if n.props.get("name") == "bounded")
    node = builder.snapshot.nodes[node_id]
    assert node.props.get("permissions_boundary_arn") == "arn:aws:iam::111111111111:policy/bound"
    assert "iam:PassRole" in (node.props.get("permissions_boundary_actions") or [])
    actions = collect_principal_actions(builder.snapshot, node_id)
    assert has_required_actions(actions, frozenset({"iam:PassRole"}))
    assert not has_required_actions(actions, frozenset({"iam:AttachRolePolicy"}))


def test_actions_from_policy_document():
    actions = actions_from_policy_document(
        {
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"]},
                {"Effect": "Deny", "Action": "s3:*"},
            ]
        }
    )
    assert actions == ["s3:GetObject", "s3:PutObject"]
