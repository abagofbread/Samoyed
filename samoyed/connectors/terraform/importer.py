from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from samoyed.cloud.artifacts import ConceptArtifact, ConceptEdge, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType
from samoyed.connectors._shared import aws_scope, build_session_from_artifacts, parse_json_payload
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
    scope_id, scope_display = aws_scope(account_id)
    if not artifacts:
        artifacts.append(
            ConceptArtifact(
                concept_type=ConceptType.IDENTITY,
                provider=CloudProvider.AWS,
                native_id=f"arn:aws:iam::{account_id}:root",
                scope_id=scope_id,
                properties={
                    "native_kind": "Root",
                    "display_name": f"account-root:{account_id}",
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
                    provider=CloudProvider.AWS,
                    native_id=placement.native_id,
                    scope_id=make_scope_for_account(placement.account_id or account_id),
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
        provider=CloudProvider.AWS,
        account_id=account_id,
        network=inventory,
        session_store=session_store,
    )
    meta["terraform_resource_count"] = len(artifacts)
    meta["provider"] = CloudProvider.AWS.value
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


def make_scope_for_account(account_id: str) -> str:
    return aws_scope(account_id or "unknown")[0]


def _from_tfstate(state: dict[str, Any]) -> tuple[NetworkInventory, list[ConceptArtifact], str]:
    resources = list(state.get("resources") or [])
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
                                    target_concept_type=(
                                        ConceptType.DATA_STORE
                                        if target.startswith("S3Bucket:")
                                        else ConceptType.SECRET_STORE
                                        if target.startswith("Secret:")
                                        else ConceptType.DATA_STORE
                                    ),
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


def _iter_policy_statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    stmt = doc.get("Statement") or []
    if isinstance(stmt, dict):
        return [stmt]
    return [s for s in stmt if isinstance(s, dict)]


def _action_to_rel(action: str) -> str | None:
    a = action.lower()
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
    if resource.startswith("arn:aws:s3:::"):
        bucket = resource.split(":::", 1)[1].split("/")[0]
        return f"S3Bucket:{bucket}" if bucket and bucket != "*" else None
    if resource.startswith("arn:aws:secretsmanager:"):
        return f"Secret:{resource}"
    if "/" not in resource and ":" not in resource:
        return f"S3Bucket:{resource}"
    return None


def _placement_props(placement: NetworkPlacement) -> dict[str, Any]:
    return {
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
        r'resource\s+"(?P<type>aws_[^"]+)"\s+"(?P<name>[^"]+)"\s*\{(?P<body>.*?)\n\}',
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
