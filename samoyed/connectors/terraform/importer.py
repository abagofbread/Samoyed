from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.capabilities import map_azure_role
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.connectors._shared import aws_scope, build_session_from_artifacts, parse_json_payload
from samoyed.cloud.providers import make_scope_id
from samoyed.graph.builder import GraphBuilder
from samoyed.network.model import NetworkInventory, NetworkPlacement, PeeringLink, SgIngressRule


def import_terraform(
    payload: bytes | str,
    *,
    session_id: str,
    caller_arn: str | None = None,
    session_store: Any | None = None,
) -> tuple[GraphBuilder, dict[str, Any]]:
    """Import a Terraform state JSON (or directory scan result) into a Samoyed session."""
    data = parse_json_payload(payload)
    if not isinstance(data, dict):
        raise ValueError("Terraform import expects a JSON object (tfstate or scan bundle)")

    if data.get("resources") is None and data.get("tfstate_files"):
        # Directory scan bundle: merge multiple states.
        inventory = NetworkInventory(source="terraform")
        artifacts: list[ConceptArtifact] = []
        account_id = "unknown"
        for entry in data.get("tfstate_files") or []:
            state = entry.get("state") if isinstance(entry, dict) else None
            if not isinstance(state, dict):
                continue
            inv, arts, acct = _from_tfstate(state)
            inventory = inventory.merge(inv)
            artifacts.extend(arts)
            if acct and acct != "unknown":
                account_id = acct
    else:
        inventory, artifacts, account_id = _from_tfstate(data)

    if not artifacts and inventory.is_empty():
        raise ValueError("No Terraform compute/network resources found")

    # Ensure at least a scope-linked placeholder identity when only network facts exist.
    if inventory.provider == "gcp":
        provider = CloudProvider.GCP
    elif inventory.provider == "azure":
        provider = CloudProvider.AZURE
    else:
        provider = CloudProvider.AWS
    if provider == CloudProvider.GCP:
        scope_id, scope_display = gcp_scope(account_id)
    elif provider == CloudProvider.AZURE:
        scope_id, scope_display = azure_scope(account_id)
    else:
        scope_id, scope_display = aws_scope(account_id)
    if not artifacts:
        if provider == CloudProvider.GCP:
            native_id = f"gcp:serviceaccount:terraform@{account_id}.iam.gserviceaccount.com"
            native_kind, display = "Project", f"project-root:{account_id}"
        elif provider == CloudProvider.AZURE:
            native_id = f"azure:serviceprincipal:terraform-{account_id}"
            native_kind, display = "ServicePrincipal", f"subscription-root:{account_id}"
        else:
            native_id = f"arn:aws:iam::{account_id}:root"
            native_kind, display = "Root", f"account-root:{account_id}"
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=provider,
                native_id=native_id,
                scope_id=scope_id,
                properties={
                    "native_kind": native_kind,
                    "display_name": display,
                    "account_id": account_id,
                    "source": "terraform",
                    "is_caller": True,
                },
                evidence=Evidence("terraform:implicit-root", {"account_id": account_id}),
            )
        )
        for placement in inventory.placements:
            artifacts.append(
                ConceptArtifact(
                    concept_type=ConceptType.RUNTIME_BINDING,
                    provider=provider,
                    native_id=placement.native_id,
                    scope_id=make_scope_for_account(placement.account_id or account_id, provider),
                    properties=_placement_props(placement),
                    evidence=Evidence("terraform:placement", {"native_id": placement.native_id}),
                )
            )

    resolved_caller = caller_arn
    if not resolved_caller:
        for art in artifacts:
            if art.properties.get("is_caller"):
                resolved_caller = art.native_id
                break

    builder, meta = build_session_from_artifacts(
        artifacts,
        session_id=session_id,
        source="terraform",
        scope_id=scope_id,
        scope_display=scope_display,
        caller_arn=resolved_caller,
        provider=provider,
        account_id=account_id,
        network=inventory,
        session_store=session_store,
    )
    meta["terraform_resource_count"] = len(artifacts)
    meta["provider"] = provider.value
    return builder, meta


def parse_tfstate_to_inventory(state: dict[str, Any]) -> NetworkInventory:
    inventory, _artifacts, _account = _from_tfstate(state)
    return inventory


def detect_terraform_path(path: Path) -> bool:
    path = Path(path)
    if path.is_file():
        name = path.name.lower()
        return name.endswith(".tfstate") or name.endswith(".tf") or name.endswith(".tf.json")
    if path.is_dir():
        for child in path.rglob("*"):
            if child.is_file() and detect_terraform_path(child):
                return True
    return False


def load_terraform_from_path(path: Path) -> dict[str, Any]:
    """Load tfstate JSON or a directory of states into an importable payload."""
    path = Path(path)
    if path.is_file():
        if path.name.endswith(".tfstate") or path.suffix == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        if path.suffix == ".tf" or path.name.endswith(".tf.json"):
            # Best-effort: wrap HCL-derived pseudo-state (limited).
            return _hcl_file_to_pseudo_state(path)
        raise ValueError(f"Unsupported terraform path: {path}")

    states: list[dict[str, Any]] = []
    for state_path in sorted(path.rglob("*.tfstate")):
        try:
            states.append({"path": str(state_path), "state": json.loads(state_path.read_text(encoding="utf-8"))})
        except (OSError, json.JSONDecodeError):
            continue
    if states:
        return {"tfstate_files": states, "source": "terraform-directory"}

    # Fall back to light HCL parse of .tf files in the tree.
    resources: list[dict[str, Any]] = []
    for tf_path in sorted(path.rglob("*.tf")):
        resources.extend(_parse_tf_resources_light(tf_path))
    for tf_path in sorted(path.rglob("*.tf.json")):
        try:
            data = json.loads(tf_path.read_text(encoding="utf-8"))
            resources.extend(_resources_from_tf_json(data))
        except (OSError, json.JSONDecodeError):
            continue
    if not resources:
        raise ValueError(f"No terraform state or resources found under {path}")
    return {"version": 4, "resources": resources, "source": "terraform-hcl"}


def gcp_scope(project_id: str) -> tuple[str, str]:
    project_id = project_id or "unknown"
    return make_scope_id(CloudProvider.GCP, "project", project_id), f"GCP project {project_id}"


def azure_scope(subscription_id: str) -> tuple[str, str]:
    subscription_id = subscription_id or "unknown"
    return (
        make_scope_id(CloudProvider.AZURE, "subscription", subscription_id),
        f"Azure subscription {subscription_id}",
    )


def make_scope_for_account(account_id: str, provider: CloudProvider = CloudProvider.AWS) -> str:
    if provider == CloudProvider.GCP:
        return gcp_scope(account_id)[0]
    if provider == CloudProvider.AZURE:
        return azure_scope(account_id)[0]
    return aws_scope(account_id)[0]


def _from_tfstate(state: dict[str, Any]) -> tuple[NetworkInventory, list[ConceptArtifact], str]:
    resources = list(state.get("resources") or [])
    if any(str(resource.get("type") or "").startswith("azurerm_") for resource in resources):
        return _from_azure_tfstate(state)
    if any(str(resource.get("type") or "").startswith("google_") for resource in resources):
        return _from_gcp_tfstate(state)
    inventory = NetworkInventory(provider="aws", source="terraform")
    artifacts: list[ConceptArtifact] = []
    account_id = "unknown"

    # Index attributes by type for cross-links.
    instances: list[dict[str, Any]] = []
    lambdas: list[dict[str, Any]] = []
    load_balancers: list[dict[str, Any]] = []
    buckets: list[dict[str, Any]] = []
    role_policies: list[dict[str, Any]] = []
    lb_targets: list[dict[str, Any]] = []
    security_groups: dict[str, dict[str, Any]] = {}
    vpcs: dict[str, dict[str, Any]] = {}
    peerings: list[dict[str, Any]] = []
    instance_profiles: dict[str, str] = {}

    for res in resources:
        mode = res.get("mode") or "managed"
        if mode not in {"managed", "data"}:
            continue
        rtype = res.get("type") or ""
        for inst in res.get("instances") or [{"attributes": res.get("attributes") or {}}]:
            attrs = inst.get("attributes") or {}
            if not attrs and "values" in inst:
                attrs = inst.get("values") or {}
            entry = {"name": res.get("name"), "type": rtype, "attrs": attrs}
            if rtype == "aws_instance":
                instances.append(entry)
            elif rtype == "aws_lambda_function":
                lambdas.append(entry)
            elif rtype in {"aws_lb", "aws_alb", "aws_elb"}:
                load_balancers.append(entry)
            elif rtype == "aws_s3_bucket":
                buckets.append(entry)
            elif rtype in {"aws_iam_role_policy", "aws_iam_policy"}:
                role_policies.append(entry)
            elif rtype in {"aws_lb_target_group_attachment", "aws_alb_target_group_attachment"}:
                lb_targets.append(entry)
            elif rtype == "aws_security_group":
                sg_id = attrs.get("id") or attrs.get("arn") or f"sg:{res.get('name')}"
                security_groups[str(sg_id)] = attrs
            elif rtype == "aws_vpc":
                vpc_id = attrs.get("id") or f"vpc:{res.get('name')}"
                vpcs[str(vpc_id)] = attrs
            elif rtype == "aws_vpc_peering_connection":
                peerings.append(entry)
            elif rtype == "aws_iam_instance_profile":
                profile_id = attrs.get("id") or attrs.get("name") or res.get("name")
                role = attrs.get("role")
                if profile_id and role:
                    role_arn = role if str(role).startswith("arn:") else None
                    instance_profiles[str(profile_id)] = role_arn or str(role)
            elif rtype == "aws_iam_role":
                arn = attrs.get("arn")
                name = attrs.get("name") or res.get("name")
                if arn:
                    artifacts.append(
                        ConceptArtifact(
                            concept_type=ConceptType.IDENTITY,
                            provider=CloudProvider.AWS,
                            native_id=arn,
                            scope_id=make_scope_for_account(_account_from_arn(arn) or account_id),
                            properties={
                                "native_kind": "Role",
                                "name": name,
                                "arn": arn,
                                "display_name": name or arn,
                                "source": "terraform",
                            },
                            evidence=Evidence("terraform:aws_iam_role", {"arn": arn}),
                        )
                    )
                    account_id = _account_from_arn(arn) or account_id

    for vpc_id, attrs in vpcs.items():
        cidrs: list[str] = []
        if attrs.get("cidr_block"):
            cidrs.append(str(attrs["cidr_block"]))
        for block in attrs.get("cidr_block_association_set") or []:
            if isinstance(block, dict) and block.get("cidr_block"):
                cidrs.append(str(block["cidr_block"]))
        for c in attrs.get("ipv6_cidr_blocks") or []:
            cidrs.append(str(c))
        if cidrs:
            inventory.vpc_cidrs[vpc_id] = sorted(set(cidrs))
        owner = attrs.get("owner_id")
        if owner and account_id == "unknown":
            account_id = str(owner)

    for sg_id, attrs in security_groups.items():
        for perm in attrs.get("ingress") or []:
            if not isinstance(perm, dict):
                continue
            cidrs = [str(c) for c in (perm.get("cidr_blocks") or [])]
            cidrs.extend(str(c) for c in (perm.get("ipv6_cidr_blocks") or []))
            refs = [str(block) for block in (perm.get("security_groups") or [])]
            if perm.get("self"):
                refs.append(str(sg_id))
            inventory.sg_rules.append(
                SgIngressRule(
                    sg_id=str(sg_id),
                    direction="ingress",
                    cidrs=cidrs,
                    referenced_sg_ids=refs,
                    from_port=perm.get("from_port"),
                    to_port=perm.get("to_port"),
                    protocol=str(perm.get("protocol") or "-1"),
                )
            )
        owner = attrs.get("owner_id")
        if owner and account_id == "unknown":
            account_id = str(owner)

    for entry in peerings:
        attrs = entry["attrs"]
        pcx_id = str(attrs.get("id") or entry.get("name") or "pcx-unknown")
        accepter = attrs.get("accepter") or {}
        requester = attrs.get("requester") or {}
        if isinstance(accepter, list):
            accepter = accepter[0] if accepter else {}
        if isinstance(requester, list):
            requester = requester[0] if requester else {}
        local_vpc = str(attrs.get("vpc_id") or requester.get("vpc_id") or "")
        remote_vpc = str(
            attrs.get("peer_vpc_id") or accepter.get("vpc_id") or attrs.get("peer_vpc_id") or ""
        )
        local_account = str(
            attrs.get("owner_id")
            or requester.get("owner_id")
            or _account_hint(attrs, "local")
            or account_id
        )
        remote_account = str(
            attrs.get("peer_owner_id")
            or accepter.get("owner_id")
            or _account_hint(attrs, "peer")
            or ""
        )
        status = str(attrs.get("accept_status") or attrs.get("status") or "active")
        local_cidrs = list(inventory.vpc_cidrs.get(local_vpc, []))
        remote_cidrs = list(inventory.vpc_cidrs.get(remote_vpc, []))
        for key in ("cidr_block", "peer_cidr_block"):
            if attrs.get(key):
                (local_cidrs if key == "cidr_block" else remote_cidrs).append(str(attrs[key]))
        inventory.peerings.append(
            PeeringLink(
                id=pcx_id,
                status=status,
                local_vpc_id=local_vpc,
                local_account_id=local_account,
                remote_vpc_id=remote_vpc,
                remote_account_id=remote_account,
                local_cidrs=sorted(set(local_cidrs)),
                remote_cidrs=sorted(set(remote_cidrs)),
                provider="aws",
            )
        )
        if local_account and account_id == "unknown":
            account_id = local_account

    for entry in instances:
        attrs = entry["attrs"]
        instance_id = str(attrs.get("id") or attrs.get("arn") or entry.get("name") or "unknown")
        if not instance_id.startswith("i-") and ":" not in instance_id:
            # Fake/demo id from name
            instance_id = f"i-{instance_id}" if not instance_id.startswith("i-") else instance_id
        native_id = f"EC2Instance:{instance_id}" if not instance_id.startswith("EC2Instance:") else instance_id
        # Normalize native_id
        if not native_id.startswith("EC2Instance:"):
            native_id = f"EC2Instance:{instance_id}"
        vpc_id = str(attrs.get("vpc_id") or "")
        subnet_id = attrs.get("subnet_id")
        sg_ids = [str(x) for x in (attrs.get("vpc_security_group_ids") or attrs.get("security_groups") or [])]
        private_ip = attrs.get("private_ip")
        public_ip = attrs.get("public_ip") or attrs.get("public_ip_address")
        acct = str(attrs.get("owner_id") or account_id)
        if acct and account_id == "unknown":
            account_id = acct
        placement = NetworkPlacement(
            native_id=native_id,
            account_id=acct,
            vpc_id=vpc_id,
            subnet_ids=[str(subnet_id)] if subnet_id else [],
            private_ips=[str(private_ip)] if private_ip else [],
            public_ip=str(public_ip) if public_ip else None,
            sg_ids=sg_ids,
            resource_type="EC2Instance",
            provider="aws",
        )
        inventory.placements.append(placement)

        edges: list[ConceptEdge] = []
        profile = attrs.get("iam_instance_profile")
        role_arn = None
        if profile:
            profile_s = str(profile)
            role_arn = instance_profiles.get(profile_s)
            if not role_arn and profile_s.startswith("arn:"):
                role_arn = profile_s.replace(":instance-profile/", ":role/").replace(
                    "instance-profile/", "role/"
                )
            elif role_arn and not str(role_arn).startswith("arn:"):
                role_arn = f"arn:aws:iam::{acct}:role/{role_arn}"
            if role_arn:
                edges.append(
                    ConceptEdge(
                        rel_type="EXECUTES_AS",
                        target_native_id=role_arn,
                        target_concept_type=ConceptType.IDENTITY,
                        props={"role_arn": role_arn, "resource_type": "EC2Instance"},
                    )
                )
                artifacts.append(
                    ConceptArtifact(
                        concept_type=ConceptType.IDENTITY,
                        provider=CloudProvider.AWS,
                        native_id=role_arn,
                        scope_id=make_scope_for_account(acct),
                        properties={
                            "native_kind": "Role",
                            "arn": role_arn,
                            "display_name": role_arn.split("/")[-1],
                            "source": "terraform",
                        },
                        evidence=Evidence("terraform:instance-profile", {"role": role_arn}),
                    )
                )

        props = _placement_props(placement)
        props["instance_id"] = instance_id if instance_id.startswith("i-") else attrs.get("id") or instance_id
        props["state"] = attrs.get("instance_state") or attrs.get("state") or "running"
        props["execution_role_arn"] = role_arn
        props["is_caller"] = bool(attrs.get("is_caller") or attrs.get("tags", {}).get("samoyed_caller"))
        if isinstance(attrs.get("tags"), dict) and attrs["tags"].get("Name"):
            props["display_name"] = attrs["tags"]["Name"]
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.AWS,
                native_id=native_id,
                scope_id=make_scope_for_account(acct),
                properties=props,
                evidence=Evidence("terraform:aws_instance", {"id": native_id}),
                edges=edges,
            )
        )

    for entry in lambdas:
        attrs = entry["attrs"]
        fn_arn = str(attrs.get("arn") or "")
        fn_name = str(attrs.get("function_name") or entry.get("name") or "function")
        if not fn_arn:
            acct = account_id if account_id != "unknown" else "000000000000"
            fn_arn = f"arn:aws:lambda:us-east-1:{acct}:function:{fn_name}"
        native_id = f"LambdaFunction:{fn_arn}"
        vpc_config = attrs.get("vpc_config") or {}
        if isinstance(vpc_config, list):
            vpc_config = vpc_config[0] if vpc_config else {}
        subnet_ids = [str(x) for x in (vpc_config.get("subnet_ids") or [])]
        sg_ids = [str(x) for x in (vpc_config.get("security_group_ids") or [])]
        vpc_id = str(vpc_config.get("vpc_id") or "")
        acct = _account_from_arn(fn_arn) or account_id
        placement = NetworkPlacement(
            native_id=native_id,
            account_id=acct,
            vpc_id=vpc_id,
            subnet_ids=subnet_ids,
            sg_ids=sg_ids,
            resource_type="LambdaFunction",
            provider="aws",
        )
        if vpc_id or sg_ids:
            inventory.placements.append(placement)
        role = attrs.get("role")
        edges = []
        if role:
            edges.append(
                ConceptEdge(
                    rel_type="EXECUTES_AS",
                    target_native_id=str(role),
                    target_concept_type=ConceptType.IDENTITY,
                    props={"role_arn": role, "resource_type": "LambdaFunction"},
                )
            )
        props = _placement_props(placement)
        props.update(
            {
                "function_name": fn_name,
                "arn": fn_arn,
                "execution_role_arn": role,
                "resource_type": "LambdaFunction",
                "source": "terraform",
            }
        )
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.AWS,
                native_id=native_id,
                scope_id=make_scope_for_account(acct),
                properties=props,
                evidence=Evidence("terraform:aws_lambda_function", {"arn": fn_arn}),
                edges=edges,
            )
        )

    for entry in load_balancers:
        attrs = entry["attrs"]
        lb_arn = str(attrs.get("arn") or attrs.get("id") or entry.get("name") or "lb")
        lb_name = str(attrs.get("name") or entry.get("name") or lb_arn)
        native_id = f"LoadBalancer:{lb_arn}" if not lb_arn.startswith("LoadBalancer:") else lb_arn
        if attrs.get("scheme"):
            scheme = str(attrs["scheme"])
        elif attrs.get("internal") is True:
            scheme = "internal"
        elif attrs.get("internal") is False:
            scheme = "internet-facing"
        else:
            scheme = "internet-facing"
        sg_ids = [str(x) for x in (attrs.get("security_groups") or [])]
        subnet_ids = [str(x) for x in (attrs.get("subnets") or [])]
        vpc_id = str(attrs.get("vpc_id") or "")
        acct = _account_from_arn(lb_arn) or str(attrs.get("owner_id") or account_id)
        dns = attrs.get("dns_name")
        internet_facing = scheme == "internet-facing"
        placement = NetworkPlacement(
            native_id=native_id,
            account_id=acct,
            vpc_id=vpc_id,
            subnet_ids=subnet_ids,
            sg_ids=sg_ids,
            public_ip=str(dns) if internet_facing and dns else None,
            exposed_internet=internet_facing,
            resource_type="LoadBalancer",
            provider="aws",
        )
        inventory.placements.append(placement)
        props = _placement_props(placement)
        props.update(
            {
                "resource_type": "LoadBalancer",
                "display_name": lb_name,
                "arn": lb_arn if str(lb_arn).startswith("arn:") else None,
                "scheme": scheme,
                "dns_name": dns,
                "has_public_url": internet_facing,
                "exposed_internet": internet_facing,
                "source": "terraform",
            }
        )
        if isinstance(attrs.get("tags"), dict) and attrs["tags"].get("Name"):
            props["display_name"] = attrs["tags"]["Name"]
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.AWS,
                native_id=native_id,
                scope_id=make_scope_for_account(acct),
                properties=props,
                evidence=Evidence("terraform:aws_lb", {"arn": lb_arn}),
            )
        )

    for entry in buckets:
        attrs = entry["attrs"]
        name = str(attrs.get("bucket") or attrs.get("id") or entry.get("name") or "")
        if not name:
            continue
        native_id = f"S3Bucket:{name}"
        acct = str(attrs.get("owner_id") or account_id)
        arn = str(attrs.get("arn") or f"arn:aws:s3:::{name}")
        tags = attrs.get("tags") if isinstance(attrs.get("tags"), dict) else {}
        public = bool(
            attrs.get("acl") == "public-read"
            or tags.get("public")
            or attrs.get("public_read")
        )
        props = {
            "resource_type": "S3Bucket",
            "bucket_name": name,
            "arn": arn,
            "display_name": tags.get("Name") or name,
            "account_id": acct,
            "source": "terraform",
            "sensitivity": tags.get("sensitivity") or tags.get("Sensitivity"),
            "public_read": public,
            "has_public_url": public,
        }
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.DATA_STORE,
                provider=CloudProvider.AWS,
                native_id=native_id,
                scope_id=make_scope_for_account(acct),
                properties=props,
                evidence=Evidence("terraform:aws_s3_bucket", {"bucket": name}),
            )
        )

    # IAM role policies → capability edges onto buckets / resources.
    for entry in role_policies:
        attrs = entry["attrs"]
        role = attrs.get("role") or attrs.get("name")
        policy = attrs.get("policy")
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                policy = None
        if not role or not isinstance(policy, dict):
            continue
        role_arn = str(role) if str(role).startswith("arn:") else f"arn:aws:iam::{account_id}:role/{role}"
        for stmt in _iter_policy_statements(policy):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action") or []
            if isinstance(actions, str):
                actions = [actions]
            resources_list = stmt.get("Resource") or []
            if isinstance(resources_list, str):
                resources_list = [resources_list]
            for action in actions:
                rel = _action_to_rel(str(action))
                if not rel:
                    continue
                for resource in resources_list:
                    target = _resource_to_native_id(str(resource))
                    if not target:
                        continue
                    if rel == "CAN_ASSUME_ROLE" or target.startswith("arn:aws:iam:"):
                        target_concept = ConceptType.IDENTITY
                    elif target.startswith("S3Bucket:"):
                        target_concept = ConceptType.DATA_STORE
                    elif target.startswith("Secret:"):
                        target_concept = ConceptType.SECRET_STORE
                    else:
                        target_concept = ConceptType.DATA_STORE
                    artifacts.append(
                        ConceptArtifact(
                            concept_type=ConceptType.ENTITLEMENT,
                            provider=CloudProvider.AWS,
                            native_id=f"terraform:policy:{role_arn}:{action}:{target}",
                            scope_id=make_scope_for_account(_account_from_arn(role_arn) or account_id),
                            properties={
                                "policy_name": attrs.get("name") or entry.get("name"),
                                "principal_arn": role_arn,
                                "source": "terraform",
                            },
                            evidence=Evidence("terraform:aws_iam_role_policy", {"role": role_arn}),
                            edges=[
                                ConceptEdge(
                                    rel_type=rel,
                                    src_native_id=role_arn,
                                    target_native_id=target,
                                    target_concept_type=target_concept,
                                    props={"action": action, "resource": resource, "source": "terraform"},
                                )
                            ],
                        )
                    )

    # Explicit LB → instance target edges (network path via target group).
    for entry in lb_targets:
        attrs = entry["attrs"]
        target_id = attrs.get("target_id") or attrs.get("instance")
        lb_arn = attrs.get("load_balancer_arn") or attrs.get("lb_arn")
        # Tags often carry the LB native id in demo fixtures.
        tags = attrs.get("tags") if isinstance(attrs.get("tags"), dict) else {}
        lb_ref = lb_arn or tags.get("load_balancer") or tags.get("lb")
        if not target_id or not lb_ref:
            continue
        lb_native = str(lb_ref) if str(lb_ref).startswith("LoadBalancer:") else f"LoadBalancer:{lb_ref}"
        inst_native = (
            str(target_id)
            if str(target_id).startswith("EC2Instance:")
            else f"EC2Instance:{target_id}"
        )
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.RUNTIME_BINDING,
                provider=CloudProvider.AWS,
                native_id=lb_native,
                scope_id=make_scope_for_account(account_id),
                properties={"resource_type": "LoadBalancer", "source": "terraform"},
                evidence=Evidence("terraform:lb_target", {"lb": lb_native, "target": inst_native}),
                edges=[
                    ConceptEdge(
                        rel_type="CAN_REACH",
                        target_native_id=inst_native,
                        target_concept_type=ConceptType.RUNTIME_BINDING,
                        props={
                            "source": "terraform",
                            "mechanism": "lb-target",
                            "confidence": "explicit",
                        },
                    )
                ],
            )
        )

    # Deduplicate identity artifacts by native_id
    seen: set[str] = set()
    deduped: list[ConceptArtifact] = []
    for art in artifacts:
        if art.native_id in seen and art.concept_type != ConceptType.ENTITLEMENT:
            # Merge edges onto first sighting for LB target stubs etc.
            existing = next(a for a in deduped if a.native_id == art.native_id)
            existing.edges.extend(art.edges)
            existing.properties.update({k: v for k, v in art.properties.items() if v is not None})
            continue
        if art.native_id in seen and art.concept_type == ConceptType.ENTITLEMENT:
            deduped.append(art)
            continue
        seen.add(art.native_id)
        deduped.append(art)

    # Mark first EC2 with public IP / open SG as scenario start if none marked.
    if not any(a.properties.get("is_caller") for a in deduped):
        for art in deduped:
            if art.concept_type == ConceptType.RUNTIME_BINDING and art.properties.get("public_ip"):
                art.properties["is_caller"] = True
                art.properties["is_scenario_start"] = True
                break

    return inventory, deduped, account_id


def _from_azure_tfstate(state: dict[str, Any]) -> tuple[NetworkInventory, list[ConceptArtifact], str]:
    """Extract portable Azure identity, workload, and network artifacts from tfstate."""
    resources = list(state.get("resources") or [])
    inventory = NetworkInventory(provider="azure", source="terraform")
    artifacts: list[ConceptArtifact] = []
    subscription_id = _azure_subscription_from_provider(state) or "unknown"
    entries: list[dict[str, Any]] = []
    vnets: dict[str, dict[str, Any]] = {}
    mi_by_id: dict[str, str] = {}  # ARM id or name → principal_id
    mi_by_principal: dict[str, str] = {}  # principal_id → native_id
    known_resources: dict[str, str] = {}  # ARM id / name → native_id
    secret_by_vault: dict[str, list[str]] = {}

    for res in resources:
        rtype = str(res.get("type") or "")
        if not rtype.startswith("azurerm_") or (res.get("mode") or "managed") not in {"managed", "data"}:
            continue
        for inst in res.get("instances") or [{"attributes": res.get("attributes") or {}}]:
            attrs = inst.get("attributes") or inst.get("values") or {}
            if not isinstance(attrs, dict):
                attrs = {}
            entry = {"type": rtype, "name": res.get("name"), "attrs": attrs}
            entries.append(entry)
            subscription_id = _azure_subscription_id(attrs, subscription_id)
            if rtype == "azurerm_virtual_network":
                vnet_key = str(attrs.get("id") or attrs.get("name") or res.get("name"))
                vnets[vnet_key] = attrs
            elif rtype == "azurerm_user_assigned_identity":
                principal = str(attrs.get("principal_id") or "")
                arm_id = str(attrs.get("id") or "")
                name = str(attrs.get("name") or res.get("name") or "")
                if principal:
                    native = f"azure:managedidentity:{principal}"
                    mi_by_principal[principal] = native
                    if arm_id:
                        mi_by_id[arm_id] = principal
                    if name:
                        mi_by_id[name] = principal
                        mi_by_id[name.lower()] = principal

    for vnet_id, attrs in vnets.items():
        cidrs = [str(c) for c in (attrs.get("address_space") or []) if c]
        if attrs.get("address_prefix"):
            cidrs.append(str(attrs["address_prefix"]))
        if cidrs:
            inventory.vpc_cidrs[vnet_id] = sorted(set(cidrs))
            name = str(attrs.get("name") or "")
            if name and name not in inventory.vpc_cidrs:
                inventory.vpc_cidrs[name] = list(inventory.vpc_cidrs[vnet_id])

    role_assignments: list[dict[str, Any]] = []

    for entry in entries:
        rtype, attrs = entry["type"], entry["attrs"]
        sub = _azure_subscription_id(attrs, subscription_id)
        scope = make_scope_for_account(sub, CloudProvider.AZURE)
        name = str(attrs.get("name") or entry["name"] or "unknown")
        arm_id = str(attrs.get("id") or "")

        if rtype == "azurerm_role_assignment":
            role_assignments.append(entry)
            continue

        if rtype == "azurerm_subnet":
            network = str(
                attrs.get("virtual_network_id")
                or attrs.get("virtual_network_name")
                or ""
            )
            prefixes = [str(p) for p in (attrs.get("address_prefixes") or []) if p]
            if attrs.get("address_prefix"):
                prefixes.append(str(attrs["address_prefix"]))
            if network and prefixes:
                inventory.vpc_cidrs.setdefault(network, []).extend(prefixes)
        elif rtype == "azurerm_network_security_group":
            nsg_id = arm_id or f"nsg:{name}"
            for rule in attrs.get("security_rule") or []:
                if isinstance(rule, dict):
                    inventory.sg_rules.append(_azure_sg_rule(nsg_id, rule))
        elif rtype == "azurerm_network_security_rule":
            nsg_id = str(
                attrs.get("network_security_group_id")
                or attrs.get("network_security_group_name")
                or f"nsg:{name}"
            )
            inventory.sg_rules.append(_azure_sg_rule(nsg_id, attrs))
        elif rtype == "azurerm_virtual_network_peering":
            local = str(
                attrs.get("virtual_network_id")
                or attrs.get("virtual_network_name")
                or ""
            )
            remote = str(attrs.get("remote_virtual_network_id") or "")
            local_sub = _azure_subscription_from_resource_id(local) or sub
            remote_sub = _azure_subscription_from_resource_id(remote) or sub
            inventory.peerings.append(
                PeeringLink(
                    id=str(attrs.get("id") or attrs.get("name") or name),
                    status="active" if attrs.get("allow_virtual_network_access", True) else "inactive",
                    local_vpc_id=local,
                    remote_vpc_id=remote,
                    local_account_id=local_sub,
                    remote_account_id=remote_sub,
                    local_cidrs=list(inventory.vpc_cidrs.get(local, [])),
                    remote_cidrs=list(inventory.vpc_cidrs.get(remote, [])),
                    provider="azure",
                )
            )
        elif rtype == "azurerm_user_assigned_identity":
            principal = str(attrs.get("principal_id") or "")
            if not principal:
                continue
            native = f"azure:managedidentity:{principal}"
            artifacts.append(
                _azure_identity(native, sub, "ManagedIdentity", "terraform:azurerm_user_assigned_identity", name)
            )
        elif rtype in {"azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"}:
            native_id = f"AzureVM:{arm_id or name}"
            known_resources[arm_id] = native_id
            known_resources[name] = native_id
            vnet_id, subnet_ids, private_ips, public_ip, sg_ids = _azure_vm_network(attrs)
            placement = NetworkPlacement(
                native_id=native_id,
                account_id=sub,
                vpc_id=vnet_id,
                subnet_ids=subnet_ids,
                private_ips=private_ips,
                public_ip=public_ip,
                sg_ids=sg_ids,
                resource_type="AzureVM",
                provider="azure",
            )
            inventory.placements.append(placement)
            edges, mi_native = _azure_executes_as_edges(attrs, mi_by_id, mi_by_principal, sub, artifacts)
            props = _placement_props(placement)
            props.update(
                {
                    "display_name": name,
                    "resource_type": "AzureVM",
                    "execution_role_arn": mi_native,
                    "is_caller": bool(public_ip),
                    "is_scenario_start": bool(public_ip),
                }
            )
            artifacts.append(
                ConceptArtifact(
                    ConceptType.RUNTIME_BINDING,
                    CloudProvider.AZURE,
                    native_id,
                    scope,
                    props,
                    Evidence(f"terraform:{rtype}", {"id": native_id}),
                    edges=edges,
                )
            )
        elif rtype in {
            "azurerm_linux_function_app",
            "azurerm_windows_function_app",
            "azurerm_function_app",
            "azurerm_linux_web_app",
            "azurerm_windows_web_app",
            "azurerm_app_service",
        }:
            kind = "FunctionApp" if "function" in rtype else "WebApp"
            native_id = f"{kind}:{name}"
            known_resources[arm_id] = native_id
            known_resources[name] = native_id
            edges, mi_native = _azure_executes_as_edges(attrs, mi_by_id, mi_by_principal, sub, artifacts)
            artifacts.append(
                ConceptArtifact(
                    ConceptType.RUNTIME_BINDING,
                    CloudProvider.AZURE,
                    native_id,
                    scope,
                    {
                        "resource_type": kind,
                        "display_name": name,
                        "subscription_id": sub,
                        "execution_role_arn": mi_native,
                        "source": "terraform",
                    },
                    Evidence(f"terraform:{rtype}", {"id": native_id}),
                    edges=edges,
                )
            )
        elif rtype == "azurerm_key_vault":
            native_id = f"KeyVault:{name}"
            known_resources[arm_id] = native_id
            known_resources[name] = native_id
            artifacts.append(
                ConceptArtifact(
                    ConceptType.SECRET_STORE,
                    CloudProvider.AZURE,
                    native_id,
                    scope,
                    {
                        "resource_type": "KeyVault",
                        "vault_name": name,
                        "display_name": name,
                        "subscription_id": sub,
                        "source": "terraform",
                    },
                    Evidence("terraform:azurerm_key_vault", {"vault": name}),
                )
            )
        elif rtype == "azurerm_key_vault_secret":
            vault = str(attrs.get("key_vault_id") or "")
            vault_name = _azure_resource_name(vault) or "vault"
            secret_name = str(attrs.get("name") or name)
            native_id = f"KeyVaultSecret:{vault_name}/{secret_name}"
            secret_by_vault.setdefault(vault_name, []).append(native_id)
            known_resources[arm_id] = native_id
            artifacts.append(
                ConceptArtifact(
                    ConceptType.SECRET_STORE,
                    CloudProvider.AZURE,
                    native_id,
                    scope,
                    {
                        "resource_type": "KeyVaultSecret",
                        "secret_name": secret_name,
                        "vault_name": vault_name,
                        "display_name": f"{vault_name}/{secret_name}",
                        "subscription_id": sub,
                        "source": "terraform",
                        "high_value": True,
                    },
                    Evidence("terraform:azurerm_key_vault_secret", {"secret": secret_name}),
                )
            )
        elif rtype == "azurerm_storage_account":
            native_id = f"StorageAccount:{name}"
            known_resources[arm_id] = native_id
            known_resources[name] = native_id
            artifacts.append(
                ConceptArtifact(
                    ConceptType.DATA_STORE,
                    CloudProvider.AZURE,
                    native_id,
                    scope,
                    {
                        "resource_type": "StorageAccount",
                        "account_name": name,
                        "display_name": name,
                        "subscription_id": sub,
                        "source": "terraform",
                    },
                    Evidence("terraform:azurerm_storage_account", {"account": name}),
                )
            )
        elif rtype == "azurerm_container_registry":
            native_id = f"AcrRegistry:{name}"
            known_resources[arm_id] = native_id
            known_resources[name] = native_id
            artifacts.append(
                ConceptArtifact(
                    ConceptType.REGISTRY_STORE,
                    CloudProvider.AZURE,
                    native_id,
                    scope,
                    {
                        "resource_type": "AcrRegistry",
                        "display_name": name,
                        "subscription_id": sub,
                        "source": "terraform",
                    },
                    Evidence("terraform:azurerm_container_registry", {"registry": name}),
                )
            )
        elif rtype == "azurerm_automation_account":
            native_id = f"AutomationAccount:{name}"
            known_resources[arm_id] = native_id
            known_resources[name] = native_id
            edges, mi_native = _azure_executes_as_edges(attrs, mi_by_id, mi_by_principal, sub, artifacts)
            artifacts.append(
                ConceptArtifact(
                    ConceptType.RUNTIME_BINDING,
                    CloudProvider.AZURE,
                    native_id,
                    scope,
                    {
                        "resource_type": "AutomationAccount",
                        "display_name": name,
                        "subscription_id": sub,
                        "execution_role_arn": mi_native,
                        "source": "terraform",
                    },
                    Evidence("terraform:azurerm_automation_account", {"id": native_id}),
                    edges=edges,
                )
            )
        elif rtype == "azurerm_federated_identity_credential":
            parent = str(attrs.get("parent_id") or "")
            principal = mi_by_id.get(parent) or _azure_principal_from_identity_id(parent)
            mi_native = f"azure:managedidentity:{principal}" if principal else parent
            issuer = str(attrs.get("issuer") or "")
            subject = str(attrs.get("subject") or "")
            trust_id = f"AzureFIC:{attrs.get('id') or name}"
            artifacts.append(
                ConceptArtifact(
                    ConceptType.TRUST,
                    CloudProvider.AZURE,
                    trust_id,
                    scope,
                    {
                        "native_kind": "FederatedIdentityCredential",
                        "display_name": name,
                        "issuer": issuer,
                        "subject": subject,
                        "subscription_id": sub,
                        "source": "terraform",
                    },
                    Evidence("terraform:azurerm_federated_identity_credential", {"id": trust_id}),
                )
            )
            if mi_native:
                if principal and mi_native not in mi_by_principal.values():
                    artifacts.append(
                        _azure_identity(
                            mi_native, sub, "ManagedIdentity", "terraform:federated-parent", name
                        )
                    )
                artifacts.append(
                    ConceptArtifact(
                        ConceptType.ENTITLEMENT,
                        CloudProvider.AZURE,
                        f"terraform:azure-fic:{trust_id}:{mi_native}",
                        scope,
                        {
                            "principal": trust_id,
                            "target": mi_native,
                            "mechanism": "wif/oidc-federation",
                            "source": "terraform",
                        },
                        Evidence("terraform:azurerm_federated_identity_credential", {"issuer": issuer}),
                        edges=[
                            ConceptEdge(
                                "CAN_ASSUME_ROLE",
                                mi_native,
                                ConceptType.IDENTITY,
                                src_native_id=trust_id,
                                props={
                                    "mechanism": "wif/oidc-federation",
                                    "issuer": issuer,
                                    "subject": subject,
                                },
                            )
                        ],
                    )
                )
    for entry in role_assignments:
        attrs = entry["attrs"]
        sub = _azure_subscription_id(attrs, subscription_id)
        scope = make_scope_for_account(sub, CloudProvider.AZURE)
        name = str(attrs.get("name") or entry["name"] or "unknown")
        role_name = str(
            attrs.get("role_definition_name")
            or _azure_role_name_from_id(attrs.get("role_definition_id"))
            or ""
        )
        mapping = map_azure_role(role_name) if role_name else None
        if not mapping:
            continue
        principal_raw = str(attrs.get("principal_id") or "")
        principal_type = str(attrs.get("principal_type") or "ServicePrincipal")
        if principal_raw in mi_by_principal or principal_raw in set(mi_by_id.values()):
            principal_native = f"azure:managedidentity:{principal_raw}"
            kind = "ManagedIdentity"
        else:
            principal_native = f"azure:{principal_type.lower()}:{principal_raw}"
            kind = principal_type
        artifacts.append(
            _azure_identity(principal_native, sub, kind, "terraform:azurerm_role_assignment")
        )
        assignment_scope = str(attrs.get("scope") or "")
        targets = _azure_targets_for_assignment(
            assignment_scope, mapping, known_resources, secret_by_vault
        )
        rel = mapping.capability.value
        edges = [
            ConceptEdge(
                rel,
                target_id,
                _azure_resource_concept(mapping.resource_type, target_id),
                src_native_id=principal_native,
                props={"role": role_name, "scope": assignment_scope},
            )
            for target_id in targets
        ]
        artifacts.append(
            ConceptArtifact(
                ConceptType.ENTITLEMENT,
                CloudProvider.AZURE,
                f"terraform:azure-ra:{attrs.get('id') or attrs.get('name') or name}",
                scope,
                {
                    "role_name": role_name,
                    "principal_id": principal_raw,
                    "scope": assignment_scope,
                    "source": "terraform",
                },
                Evidence("terraform:azurerm_role_assignment", {"role": role_name}),
                edges=edges,
            )
        )

    deduped = _dedupe_artifacts(artifacts)
    if not any(a.properties.get("is_caller") for a in deduped):
        for art in deduped:
            if art.concept_type == ConceptType.RUNTIME_BINDING and art.properties.get("public_ip"):
                art.properties["is_caller"] = True
                art.properties["is_scenario_start"] = True
                break
        else:
            for art in deduped:
                if art.concept_type == ConceptType.RUNTIME_BINDING and art.properties.get(
                    "resource_type"
                ) == "AzureVM":
                    art.properties["is_caller"] = True
                    art.properties["is_scenario_start"] = True
                    break

    return inventory, deduped, subscription_id


def _azure_subscription_from_provider(state: dict[str, Any]) -> str | None:
    for key in ("subscription_id", "subscriptionId"):
        if state.get(key):
            return str(state[key])
    for conf in state.get("provider_config") or []:
        if not isinstance(conf, dict):
            continue
        exprs = conf.get("expressions") or conf.get("config") or {}
        if isinstance(exprs, dict):
            for key in ("subscription_id", "subscriptionId"):
                val = exprs.get(key)
                if isinstance(val, dict) and val.get("constant_value"):
                    return str(val["constant_value"])
                if isinstance(val, str) and val:
                    return val
    return None


def _azure_subscription_id(attrs: dict[str, Any], fallback: str = "unknown") -> str:
    for key in ("subscription_id", "subscriptionId"):
        if attrs.get(key):
            return str(attrs[key])
    for value in (attrs.get("id"), attrs.get("scope"), attrs.get("key_vault_id"), attrs.get("parent_id")):
        sub = _azure_subscription_from_resource_id(str(value or ""))
        if sub:
            return sub
    return fallback


def _azure_subscription_from_resource_id(resource_id: str) -> str | None:
    match = re.search(r"/subscriptions/([^/]+)", resource_id or "", re.I)
    return match.group(1) if match else None


def _azure_resource_name(resource_id: str) -> str | None:
    if not resource_id:
        return None
    parts = [p for p in resource_id.rstrip("/").split("/") if p]
    return parts[-1] if parts else None


def _azure_role_name_from_id(role_definition_id: Any) -> str | None:
    if not role_definition_id:
        return None
    text = str(role_definition_id)
    # Built-in role GUID map is large; keep common lab names when the id ends with a name fragment.
    if "/" in text:
        return text.rstrip("/").split("/")[-1]
    return text


def _azure_sg_rule(nsg_id: str, rule: dict[str, Any]) -> SgIngressRule:
    direction = str(rule.get("direction") or "Inbound").lower()
    if direction.startswith("in"):
        direction = "ingress"
    cidrs: list[str] = []
    for key in ("source_address_prefix", "source_address_prefixes"):
        val = rule.get(key)
        if isinstance(val, list):
            cidrs.extend(str(x) for x in val if x and str(x) not in {"*", "Internet"})
            if any(str(x) in {"*", "Internet", "0.0.0.0/0"} for x in val):
                cidrs.append("0.0.0.0/0")
        elif val:
            cidrs.append("0.0.0.0/0" if str(val) in {"*", "Internet"} else str(val))
    port = rule.get("destination_port_range") or rule.get("destination_port_ranges")
    from_port = to_port = None
    if isinstance(port, list) and port:
        port = port[0]
    if port and str(port) != "*":
        try:
            if "-" in str(port):
                a, b = str(port).split("-", 1)
                from_port, to_port = int(a), int(b)
            else:
                from_port = to_port = int(port)
        except ValueError:
            pass
    return SgIngressRule(
        sg_id=str(nsg_id),
        direction=direction,
        cidrs=cidrs,
        from_port=from_port,
        to_port=to_port,
        protocol=str(rule.get("protocol") or "*"),
    )


def _azure_vm_network(
    attrs: dict[str, Any],
) -> tuple[str, list[str], list[str], str | None, list[str]]:
    private_ips: list[str] = []
    if attrs.get("private_ip_address"):
        private_ips.append(str(attrs["private_ip_address"]))
    public_ip = attrs.get("public_ip_address")
    if isinstance(public_ip, list):
        public_ip = public_ip[0] if public_ip else None
    subnet_ids: list[str] = []
    vnet_id = ""
    for key in ("subnet_id", "virtual_network_id"):
        if attrs.get(key):
            if "subnet" in key:
                subnet_ids.append(str(attrs[key]))
            else:
                vnet_id = str(attrs[key])
    # Common tfstate shape: nested network attrs or tags for lab fixtures.
    tags = attrs.get("tags") if isinstance(attrs.get("tags"), dict) else {}
    vnet_id = vnet_id or str(tags.get("vpc_id") or tags.get("vnet_id") or attrs.get("vnet_id") or "")
    if attrs.get("subnet_ids"):
        subnet_ids.extend(str(x) for x in attrs["subnet_ids"])
    sg_ids = [str(x) for x in (attrs.get("network_security_group_ids") or attrs.get("sg_ids") or [])]
    if attrs.get("network_security_group_id"):
        sg_ids.append(str(attrs["network_security_group_id"]))
    return vnet_id, subnet_ids, private_ips, str(public_ip) if public_ip else None, sg_ids


def _azure_identity_block(attrs: dict[str, Any]) -> dict[str, Any]:
    identity = attrs.get("identity") or {}
    if isinstance(identity, list):
        identity = identity[0] if identity else {}
    return identity if isinstance(identity, dict) else {}


def _azure_executes_as_edges(
    attrs: dict[str, Any],
    mi_by_id: dict[str, str],
    mi_by_principal: dict[str, str],
    sub: str,
    artifacts: list[ConceptArtifact],
) -> tuple[list[ConceptEdge], str | None]:
    identity = _azure_identity_block(attrs)
    principal = str(identity.get("principal_id") or "")
    identity_ids = identity.get("identity_ids") or identity.get("identity_id") or []
    if isinstance(identity_ids, str):
        identity_ids = [identity_ids]
    for iid in identity_ids:
        principal = principal or mi_by_id.get(str(iid)) or _azure_principal_from_identity_id(str(iid))
    if not principal:
        return [], None
    native = f"azure:managedidentity:{principal}"
    mi_by_principal.setdefault(principal, native)
    artifacts.append(
        _azure_identity(native, sub, "ManagedIdentity", "terraform:azure-identity-block")
    )
    return [
        ConceptEdge(
            "EXECUTES_AS",
            native,
            ConceptType.IDENTITY,
            props={"resource_type": "ManagedIdentity", "mechanism": "azure-managed-identity"},
        )
    ], native


def _azure_principal_from_identity_id(arm_id: str) -> str | None:
    # Best-effort: some fixtures embed principal as a trailing GUID segment after identities/.
    match = re.search(r"/userAssignedIdentities/([^/]+)", arm_id or "", re.I)
    if match and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        match.group(1),
        re.I,
    ):
        return match.group(1)
    return None


def _azure_identity(
    native_id: str,
    subscription_id: str,
    kind: str,
    source: str,
    display_name: str | None = None,
) -> ConceptArtifact:
    return ConceptArtifact(
        ConceptType.IDENTITY,
        CloudProvider.AZURE,
        native_id,
        make_scope_for_account(subscription_id, CloudProvider.AZURE),
        {
            "native_kind": kind,
            "display_name": display_name or native_id,
            "subscription_id": subscription_id,
            "source": "terraform",
        },
        Evidence(source, {"principal": native_id}),
    )


def _azure_resource_concept(resource_type: str | None, target_id: str = "") -> ConceptType:
    if resource_type in {"KeyVaultSecret", "KeyVault"} or target_id.startswith(
        ("KeyVault:", "KeyVaultSecret:")
    ):
        return ConceptType.SECRET_STORE
    if resource_type == "StorageAccount" or target_id.startswith("StorageAccount:"):
        return ConceptType.DATA_STORE
    if resource_type == "AcrRegistry" or target_id.startswith("AcrRegistry:"):
        return ConceptType.REGISTRY_STORE
    if resource_type == "Identity" or target_id.startswith("azure:"):
        return ConceptType.IDENTITY
    if resource_type in {"AzureVM", "WebApp", "FunctionApp", "AutomationAccount"} or target_id.startswith(
        ("AzureVM:", "WebApp:", "FunctionApp:", "AutomationAccount:")
    ):
        return ConceptType.RUNTIME_BINDING
    return ConceptType.DATA_STORE


def _azure_targets_for_assignment(
    scope: str,
    mapping: Any,
    known_resources: dict[str, str],
    secret_by_vault: dict[str, list[str]],
) -> list[str]:
    targets: list[str] = []
    if scope in known_resources:
        targets.append(known_resources[scope])
    name = _azure_resource_name(scope) or ""
    if name and name in known_resources:
        targets.append(known_resources[name])

    kv_match = re.search(r"/Microsoft\.KeyVault/vaults/([^/]+)", scope or "", re.I)
    if kv_match:
        vault = kv_match.group(1)
        kid = f"KeyVault:{vault}"
        targets.append(kid)
        if mapping.resource_type == "KeyVaultSecret":
            targets.extend(secret_by_vault.get(vault, []))
            if not secret_by_vault.get(vault):
                targets.append(f"KeyVaultSecret:{vault}/*")

    storage_match = re.search(
        r"/Microsoft\.Storage/storageAccounts/([^/]+)", scope or "", re.I
    )
    if storage_match:
        targets.append(f"StorageAccount:{storage_match.group(1)}")

    web_match = re.search(r"/Microsoft\.Web/sites/([^/]+)", scope or "", re.I)
    if web_match:
        kind = mapping.resource_type if mapping.resource_type in {"WebApp", "FunctionApp"} else "WebApp"
        targets.append(f"{kind}:{web_match.group(1)}")

    auto_match = re.search(
        r"/Microsoft\.Automation/automationAccounts/([^/]+)", scope or "", re.I
    )
    if auto_match:
        targets.append(f"AutomationAccount:{auto_match.group(1)}")

    acr_match = re.search(
        r"/Microsoft\.ContainerRegistry/registries/([^/]+)", scope or "", re.I
    )
    if acr_match:
        targets.append(f"AcrRegistry:{acr_match.group(1)}")

    # Deduplicate while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for t in targets:
        if t and t not in seen:
            seen.add(t)
            ordered.append(t)
    if ordered:
        return ordered
    sub = _azure_subscription_from_resource_id(scope or "")
    if sub and re.fullmatch(r"/subscriptions/[^/]+/?", scope or "", re.I):
        return [f"azure:subscription:{sub}"]
    if mapping.resource_type:
        return [f"{mapping.resource_type}:*"]
    return [scope or "azure:subscription"]


def _from_gcp_tfstate(state: dict[str, Any]) -> tuple[NetworkInventory, list[ConceptArtifact], str]:
    """Extract portable GCP identity, workload, and network artifacts from tfstate."""
    resources = list(state.get("resources") or [])
    inventory = NetworkInventory(provider="gcp", source="terraform")
    artifacts: list[ConceptArtifact] = []
    project_id = "unknown"
    entries: list[dict[str, Any]] = []
    networks: dict[str, dict[str, Any]] = {}

    for res in resources:
        rtype = str(res.get("type") or "")
        if not rtype.startswith("google_") or (res.get("mode") or "managed") not in {"managed", "data"}:
            continue
        for inst in res.get("instances") or [{"attributes": res.get("attributes") or {}}]:
            attrs = inst.get("attributes") or inst.get("values") or {}
            entry = {"type": rtype, "name": res.get("name"), "attrs": attrs}
            entries.append(entry)
            project_id = _gcp_project_id(attrs, project_id)
            if rtype == "google_compute_network":
                networks[str(attrs.get("id") or attrs.get("self_link") or res.get("name"))] = attrs

    for network_id, attrs in networks.items():
        cidr = attrs.get("ipv4_range") or attrs.get("cidr_block")
        if cidr:
            inventory.vpc_cidrs[network_id] = [str(cidr)]

    for entry in entries:
        rtype, attrs = entry["type"], entry["attrs"]
        project = _gcp_project_id(attrs, project_id)
        scope = make_scope_for_account(project, CloudProvider.GCP)
        name = str(attrs.get("name") or entry["name"] or "unknown")

        if rtype == "google_compute_subnetwork":
            network = str(attrs.get("network") or "")
            cidr = attrs.get("ip_cidr_range")
            if network and cidr:
                inventory.vpc_cidrs.setdefault(network, []).append(str(cidr))
        elif rtype == "google_compute_firewall":
            network = str(attrs.get("network") or "")
            for allow in attrs.get("allow") or []:
                if not isinstance(allow, dict):
                    continue
                inventory.sg_rules.append(SgIngressRule(
                    sg_id=f"gcp-firewall:{name}", direction="ingress",
                    cidrs=[str(x) for x in (attrs.get("source_ranges") or [])],
                    from_port=None, to_port=None,
                    protocol=str(allow.get("protocol") or "all"),
                    referenced_sg_ids=[network] if network else [],
                ))
        elif rtype == "google_compute_network_peering":
            local = str(attrs.get("network") or "")
            remote = str(attrs.get("peer_network") or "")
            remote_project = _gcp_project_from_ref(remote) or project
            inventory.peerings.append(PeeringLink(
                id=str(attrs.get("id") or name), status=str(attrs.get("state") or "ACTIVE").lower(),
                local_vpc_id=local, remote_vpc_id=remote, local_account_id=project,
                remote_account_id=remote_project,
                local_cidrs=list(inventory.vpc_cidrs.get(local, [])),
                remote_cidrs=list(inventory.vpc_cidrs.get(remote, [])),
                provider="gcp",
            ))
        elif rtype == "google_service_account":
            email = str(attrs.get("email") or f"{name}@{project}.iam.gserviceaccount.com")
            artifacts.append(_gcp_identity(email, project, "ServiceAccount", "terraform:google_service_account"))
        elif rtype == "google_compute_instance":
            instance_id = str(attrs.get("id") or name)
            native_id = f"GCEInstance:{instance_id}"
            network_interfaces = attrs.get("network_interface") or []
            iface = network_interfaces[0] if isinstance(network_interfaces, list) and network_interfaces else {}
            if not isinstance(iface, dict):
                iface = {}
            network = str(iface.get("network") or attrs.get("network") or "")
            subnet = iface.get("subnetwork") or attrs.get("subnetwork")
            access = iface.get("access_config") or []
            public_ip = (access[0].get("nat_ip") if isinstance(access, list) and access and isinstance(access[0], dict) else None)
            private_ip = iface.get("network_ip") or attrs.get("network_ip")
            placement = NetworkPlacement(
                native_id=native_id,
                account_id=project,
                vpc_id=network,
                subnet_ids=[str(subnet)] if subnet else [],
                private_ips=[str(private_ip)] if private_ip else [],
                public_ip=str(public_ip) if public_ip else None,
                sg_ids=[],
                resource_type="GCEInstance",
                provider="gcp",
            )
            inventory.placements.append(placement)
            sa = attrs.get("service_account") or []
            sa = sa[0] if isinstance(sa, list) and sa else sa
            email = sa.get("email") if isinstance(sa, dict) else sa
            edges: list[ConceptEdge] = []
            if email:
                email = str(email)
                artifacts.append(_gcp_identity(email, project, "ServiceAccount", "terraform:gce-service-account"))
                edges.append(ConceptEdge("EXECUTES_AS", email, ConceptType.IDENTITY,
                    props={"service_account": email, "resource_type": "GCEInstance"}))
            props = _placement_props(placement)
            props.update({"display_name": name, "instance_id": instance_id, "execution_service_account": email})
            artifacts.append(ConceptArtifact(ConceptType.RUNTIME_BINDING, CloudProvider.GCP, native_id, scope, props,
                Evidence("terraform:google_compute_instance", {"id": native_id}), edges=edges))
        elif rtype in {"google_cloudfunctions_function", "google_cloudfunctions2_function", "google_cloud_run_v2_service", "google_cloud_run_service"}:
            kind = "CloudFunction" if "cloudfunctions" in rtype else "CloudRunService"
            native_id = f"{kind}:{attrs.get('id') or name}"
            sa = attrs.get("service_account_email") or attrs.get("service_account")
            template = attrs.get("template") or {}
            if isinstance(template, list):
                template = template[0] if template else {}
            if isinstance(template, dict):
                sa = sa or template.get("service_account")
            edges = []
            if sa:
                sa = str(sa)
                artifacts.append(_gcp_identity(sa, project, "ServiceAccount", f"terraform:{rtype}-service-account"))
                edges.append(ConceptEdge("EXECUTES_AS", sa, ConceptType.IDENTITY, props={"resource_type": kind}))
            artifacts.append(ConceptArtifact(ConceptType.RUNTIME_BINDING, CloudProvider.GCP, native_id, scope,
                {"resource_type": kind, "display_name": name, "project_id": project, "execution_service_account": sa, "source": "terraform"},
                Evidence(f"terraform:{rtype}", {"id": native_id}), edges=edges))
        elif rtype == "google_storage_bucket":
            bucket = str(attrs.get("name") or attrs.get("id") or name)
            artifacts.append(ConceptArtifact(ConceptType.DATA_STORE, CloudProvider.GCP, f"GCSBucket:{bucket}", scope,
                {"resource_type": "GCSBucket", "bucket_name": bucket, "display_name": bucket, "project_id": project, "source": "terraform"},
                Evidence("terraform:google_storage_bucket", {"bucket": bucket})))
        elif rtype == "google_secret_manager_secret":
            secret = str(attrs.get("secret_id") or attrs.get("name") or name)
            artifacts.append(ConceptArtifact(ConceptType.SECRET_STORE, CloudProvider.GCP, f"GCPSecret:{project}:{secret}", scope,
                {"resource_type": "GCPSecret", "secret_id": secret, "display_name": secret, "project_id": project, "source": "terraform"},
                Evidence("terraform:google_secret_manager_secret", {"secret": secret})))
        elif rtype in {"google_iam_workload_identity_pool", "google_iam_workload_identity_pool_provider"}:
            native_id = f"GCPWIF:{attrs.get('id') or name}"
            artifacts.append(ConceptArtifact(ConceptType.TRUST, CloudProvider.GCP, native_id, scope,
                {"native_kind": "WorkloadIdentityPoolProvider" if rtype.endswith("_provider") else "WorkloadIdentityPool",
                 "display_name": name, "project_id": project, "source": "terraform"},
                Evidence(f"terraform:{rtype}", {"id": native_id})))
        elif rtype in {
            "google_project_iam_binding",
            "google_project_iam_member",
            "google_service_account_iam_member",
            "google_storage_bucket_iam_member",
            "google_storage_bucket_iam_binding",
        }:
            role = str(attrs.get("role") or "")
            members = attrs.get("members") or [attrs.get("member")]
            target_sa = str(attrs.get("service_account_id") or "")
            bucket = str(attrs.get("bucket") or "")
            for member in members:
                if not member:
                    continue
                principal = _gcp_principal(str(member))
                artifacts.append(_gcp_identity(principal, project, "Principal", "terraform:gcp-iam-member"))
                target = _gcp_principal(target_sa) if target_sa else principal
                edges = []
                if "serviceAccountTokenCreator" in role or "workloadIdentityUser" in role or (
                    rtype == "google_service_account_iam_member" and target_sa
                ):
                    edges.append(
                        ConceptEdge(
                            "CAN_ASSUME_ROLE",
                            target,
                            ConceptType.IDENTITY,
                            src_native_id=principal,
                            props={"role": role, "mechanism": "gcp-iam"},
                        )
                    )
                if bucket and ("storage." in role or "objectAdmin" in role or "objectViewer" in role or "admin" in role.lower()):
                    bucket_native = f"GCSBucket:{bucket}"
                    rel = "CONTROLS" if "admin" in role.lower() else "READS"
                    edges.append(
                        ConceptEdge(
                            rel,
                            bucket_native,
                            ConceptType.DATA_STORE,
                            src_native_id=principal,
                            props={"role": role, "mechanism": "gcp-storage-iam"},
                        )
                    )
                    artifacts.append(
                        ConceptArtifact(
                            ConceptType.DATA_STORE,
                            CloudProvider.GCP,
                            bucket_native,
                            scope,
                            {
                                "resource_type": "GCSBucket",
                                "bucket_name": bucket,
                                "display_name": bucket,
                                "project_id": project,
                                "source": "terraform",
                            },
                            Evidence("terraform:gcp-storage-iam", {"bucket": bucket}),
                        )
                    )
                artifacts.append(ConceptArtifact(ConceptType.ENTITLEMENT, CloudProvider.GCP,
                    f"terraform:gcp-iam:{principal}:{role}:{target}:{bucket}", scope,
                    {"principal": principal, "role": role, "source": "terraform"},
                    Evidence(f"terraform:{rtype}", {"role": role}), edges=edges))

    return inventory, _dedupe_artifacts(artifacts), project_id


def _gcp_project_id(attrs: dict[str, Any], fallback: str = "unknown") -> str:
    project = attrs.get("project")
    if project:
        return str(project)
    for value in (attrs.get("email"), attrs.get("service_account_email"), attrs.get("service_account_id")):
        match = re.search(r"@([a-z0-9-]+)\.iam\.gserviceaccount\.com", str(value or ""))
        if match:
            return match.group(1)
    return fallback


def _gcp_project_from_ref(ref: str) -> str | None:
    match = re.search(r"projects/([^/]+)", ref)
    return match.group(1) if match else None


def _gcp_principal(value: str) -> str:
    value = value.removeprefix("serviceAccount:").removeprefix("user:").removeprefix("principal://")
    return value if value else "gcp:unknown-principal"


def _gcp_identity(native_id: str, project: str, kind: str, source: str) -> ConceptArtifact:
    return ConceptArtifact(ConceptType.IDENTITY, CloudProvider.GCP, native_id,
        make_scope_for_account(project, CloudProvider.GCP),
        {"native_kind": kind, "display_name": native_id, "project_id": project, "source": "terraform"},
        Evidence(source, {"principal": native_id}))


def _dedupe_artifacts(artifacts: list[ConceptArtifact]) -> list[ConceptArtifact]:
    result: list[ConceptArtifact] = []
    by_native: dict[str, ConceptArtifact] = {}
    for artifact in artifacts:
        if artifact.concept_type == ConceptType.ENTITLEMENT or artifact.native_id not in by_native:
            result.append(artifact)
            by_native[artifact.native_id] = artifact
        else:
            by_native[artifact.native_id].edges.extend(artifact.edges)
            by_native[artifact.native_id].properties.update(artifact.properties)
    return result


def _iter_policy_statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement") or []
    if isinstance(stmt, dict):
        return [stmt]
    return [s for s in stmt if isinstance(s, dict)]


def _action_to_rel(action: str) -> str | None:
    a = action.lower()
    if a in {"sts:assumerole", "sts:assumerolewithsaml", "sts:assumerolewithwebidentity"}:
        return "CAN_ASSUME_ROLE"
    if a in {"iam:passrole"}:
        return "CAN_ASSUME_ROLE"
    if a in {"*", "s3:*"} or a.endswith(":*") and a.startswith("s3:"):
        return "CONTROLS"
    if "put" in a or "delete" in a or "write" in a:
        return "WRITES"
    if "get" in a or "list" in a or "read" in a or "describe" in a:
        return "READS"
    if "invoke" in a:
        return "EXECUTES"
    return None


def _resource_to_native_id(resource: str) -> str | None:
    if resource in {"*", "arn:aws:s3:::*"}:
        return None
    if resource.startswith("arn:aws:iam:") and ":role/" in resource and not resource.endswith("/*"):
        # Concrete role ARN (not a wildcard path).
        if "*" not in resource.split(":role/", 1)[-1]:
            return resource
        return None
    if resource.startswith("arn:aws:s3:::"):
        bucket = resource.split(":::", 1)[1].split("/")[0]
        return f"S3Bucket:{bucket}" if bucket and bucket != "*" else None
    if resource.startswith("arn:aws:secretsmanager:"):
        return f"Secret:{resource}"
    if "/" not in resource and ":" not in resource:
        return f"S3Bucket:{resource}"
    return None


def _placement_props(placement: NetworkPlacement) -> dict[str, Any]:
    props = {
        "resource_type": placement.resource_type or "EC2Instance",
        "vpc_id": placement.vpc_id,
        "subnet_ids": list(placement.subnet_ids),
        "private_ips": list(placement.private_ips),
        "public_ip": placement.public_ip,
        "sg_ids": list(placement.sg_ids),
        "account_id": placement.account_id,
        "source": "terraform",
        "display_name": placement.native_id,
    }
    if placement.provider:
        props["provider"] = placement.provider
    return props


def _account_from_arn(arn: str | None) -> str | None:
    if not arn or not str(arn).startswith("arn:"):
        return None
    parts = str(arn).split(":")
    if len(parts) >= 5 and parts[4]:
        return parts[4]
    return None


def _account_hint(attrs: dict[str, Any], side: str) -> str | None:
    tags = attrs.get("tags") or {}
    if isinstance(tags, dict):
        for key in (f"{side}_account", "account_id", "peer_account"):
            if tags.get(key):
                return str(tags[key])
    return None


def _hcl_file_to_pseudo_state(path: Path) -> dict[str, Any]:
    return {"version": 4, "resources": _parse_tf_resources_light(path), "source": "terraform-hcl"}


def _parse_tf_resources_light(path: Path) -> list[dict[str, Any]]:
    """Very small HCL extractor for demo .tf without a full parser."""
    text = path.read_text(encoding="utf-8")
    resources: list[dict[str, Any]] = []
    pattern = re.compile(
        r'resource\s+"(?P<type>(?:aws|google|azurerm)_[^"]+)"\s+"(?P<name>[^"]+)"\s*\{(?P<body>.*?)\n\}',
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        body = match.group("body")
        attrs: dict[str, Any] = {}
        for key in (
            "vpc_id",
            "peer_vpc_id",
            "peer_owner_id",
            "cidr_block",
            "private_ip",
            "public_ip",
            "subnet_id",
            "id",
            "arn",
            "function_name",
            "role",
            "iam_instance_profile",
            "project",
            "network",
            "peer_network",
            "ip_cidr_range",
            "name",
            "email",
            "service_account_email",
            "secret_id",
            "subscription_id",
            "address_prefix",
            "virtual_network_name",
            "remote_virtual_network_id",
            "principal_id",
            "role_definition_name",
            "scope",
            "key_vault_id",
            "parent_id",
            "issuer",
            "subject",
        ):
            m = re.search(rf'{key}\s*=\s*"([^"]+)"', body)
            if m:
                attrs[key] = m.group(1)
        sg_ids = re.findall(r'vpc_security_group_ids\s*=\s*\[([^\]]+)\]', body)
        if sg_ids:
            attrs["vpc_security_group_ids"] = re.findall(r'"([^"]+)"', sg_ids[0])
        ingress_cidrs = re.findall(r'cidr_blocks\s*=\s*\[([^\]]+)\]', body)
        if match.group("type") == "aws_security_group" and ingress_cidrs:
            attrs["ingress"] = [
                {"cidr_blocks": re.findall(r'"([^"]+)"', block), "protocol": "-1", "from_port": 0, "to_port": 0}
                for block in ingress_cidrs
            ]
        if match.group("type") == "aws_security_group" and not attrs.get("id"):
            attrs["id"] = f"sg-{match.group('name')}"
        if match.group("type") == "aws_vpc" and not attrs.get("id"):
            attrs["id"] = f"vpc-{match.group('name')}"
        if match.group("type") == "aws_vpc_peering_connection" and not attrs.get("id"):
            attrs["id"] = f"pcx-{match.group('name')}"
            attrs["accept_status"] = "active"
        resources.append(
            {
                "mode": "managed",
                "type": match.group("type"),
                "name": match.group("name"),
                "instances": [{"attributes": attrs}],
            }
        )
    return resources


def _resources_from_tf_json(data: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rtype, named in (data.get("resource") or {}).items():
        if not isinstance(named, dict):
            continue
        for name, body in named.items():
            attrs = body if isinstance(body, dict) else {}
            out.append(
                {
                    "mode": "managed",
                    "type": rtype,
                    "name": name,
                    "instances": [{"attributes": attrs}],
                }
            )
    return out
