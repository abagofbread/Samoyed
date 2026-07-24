"""Parse AzureHound CE, SharpHound CE, and simple OpenGraph BloodHound JSON."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from samoyed.connectors.bloodhound.mapping import ACE_RIGHT_TO_KIND, normalize_bh_kind


@dataclass
class BHNode:
    object_id: str
    kinds: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class BHEdge:
    kind: str
    start: str
    end: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedBloodHound:
    nodes: list[BHNode] = field(default_factory=list)
    edges: list[BHEdge] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def parse_bloodhound_payload(data: Any) -> ParsedBloodHound:
    """Normalize supported BloodHound JSON shapes into nodes + edges."""
    if isinstance(data, list):
        return _parse_list_payload(data)
    if not isinstance(data, dict):
        raise ValueError("BloodHound payload must be a JSON object or array")

    # OpenGraph: {graph: {nodes, edges}} or {graph: [{nodes, edges}, ...]}
    if "graph" in data:
        return _parse_opengraph(data)

    # Bundle of CE files: {files: [{meta, data}, ...]} or {data: [...], meta} single
    if "files" in data and isinstance(data["files"], list):
        parsed = ParsedBloodHound(meta={"format": "ce-bundle", **(data.get("meta") or {})})
        for item in data["files"]:
            if isinstance(item, dict):
                _merge(parsed, parse_bloodhound_payload(item))
        return parsed

    if "meta" in data and "data" in data:
        return _parse_ce_file(data)

    # AzureHound list dump sometimes wraps under azure / tenant keys with nested arrays.
    for key in ("azure", "objects", "nodes"):
        if isinstance(data.get(key), list):
            return _parse_list_payload(data[key], meta={"format": f"azurehound-{key}"})

    # Already-normalized {nodes, edges}
    if "nodes" in data and "edges" in data:
        return _parse_opengraph({"graph": data})

    raise ValueError(
        "Unrecognized BloodHound JSON (expected OpenGraph, SharpHound/AzureHound CE meta+data, or node list)"
    )


def _merge(dest: ParsedBloodHound, src: ParsedBloodHound) -> None:
    seen = {n.object_id for n in dest.nodes}
    for node in src.nodes:
        if node.object_id not in seen:
            dest.nodes.append(node)
            seen.add(node.object_id)
    dest.edges.extend(src.edges)
    for key, value in src.meta.items():
        dest.meta.setdefault(key, value)


def _parse_opengraph(data: dict[str, Any]) -> ParsedBloodHound:
    graph = data["graph"]
    chunks: list[dict[str, Any]]
    if isinstance(graph, list):
        chunks = [g for g in graph if isinstance(g, dict)]
    elif isinstance(graph, dict):
        chunks = [graph]
    else:
        raise ValueError("OpenGraph 'graph' must be an object or array of objects")

    parsed = ParsedBloodHound(
        meta={
            "format": "opengraph",
            **(data.get("metadata") or {}),
            **(data.get("meta") or {}),
        }
    )
    for chunk in chunks:
        for raw in chunk.get("nodes") or []:
            if not isinstance(raw, dict):
                continue
            oid = str(raw.get("id") or raw.get("objectId") or raw.get("ObjectIdentifier") or "")
            if not oid:
                continue
            props = dict(raw.get("properties") or {})
            kinds = list(raw.get("kinds") or [])
            if raw.get("kind") and raw["kind"] not in kinds:
                kinds.insert(0, str(raw["kind"]))
            if not kinds and props.get("nodetype"):
                kinds = [str(props["nodetype"])]
            parsed.nodes.append(BHNode(object_id=oid, kinds=kinds, properties=props))

        for raw in chunk.get("edges") or []:
            if not isinstance(raw, dict):
                continue
            kind = normalize_bh_kind(raw.get("kind") or raw.get("type") or raw.get("rel"))
            start = _endpoint_value(raw.get("start") or raw.get("source") or raw.get("from"))
            end = _endpoint_value(raw.get("end") or raw.get("target") or raw.get("to"))
            if not kind or not start or not end:
                continue
            parsed.edges.append(
                BHEdge(
                    kind=kind,
                    start=start,
                    end=end,
                    properties=dict(raw.get("properties") or {}),
                )
            )
    _infer_tenant_meta(parsed)
    return parsed


def _endpoint_value(endpoint: Any) -> str:
    if endpoint is None:
        return ""
    if isinstance(endpoint, str):
        return endpoint
    if isinstance(endpoint, dict):
        return str(endpoint.get("value") or endpoint.get("id") or endpoint.get("name") or "")
    return str(endpoint)


def _parse_list_payload(items: list[Any], meta: dict[str, Any] | None = None) -> ParsedBloodHound:
    """AzureHound-style list of {kind, data|properties} or OpenGraph-ish node dicts."""
    parsed = ParsedBloodHound(meta={"format": "azurehound-list", **(meta or {})})
    for item in items:
        if not isinstance(item, dict):
            continue
        if "start" in item and "end" in item and ("kind" in item or "type" in item):
            kind = normalize_bh_kind(item.get("kind") or item.get("type"))
            start = _endpoint_value(item.get("start"))
            end = _endpoint_value(item.get("end"))
            if kind and start and end:
                parsed.edges.append(BHEdge(kind=kind, start=start, end=end, properties=dict(item.get("properties") or {})))
            continue
        data = item.get("data") if isinstance(item.get("data"), dict) else item
        if not isinstance(data, dict):
            continue
        oid = str(
            data.get("ObjectIdentifier")
            or data.get("objectId")
            or data.get("objectid")
            or data.get("id")
            or ""
        )
        if not oid:
            continue
        kinds: list[str] = []
        if item.get("kind"):
            kinds.append(str(item["kind"]))
        if data.get("kind"):
            kinds.append(str(data["kind"]))
        for label in data.get("kinds") or data.get("Labels") or []:
            if label not in kinds:
                kinds.append(str(label))
        props = dict(data.get("Properties") or data.get("properties") or {})
        for key in ("displayName", "name", "appId", "tenantId", "onPremisesSecurityIdentifier"):
            if data.get(key) is not None and key not in props:
                props[key if key != "displayName" else "displayname"] = data[key]
        parsed.nodes.append(BHNode(object_id=oid, kinds=kinds or ["AZBase"], properties=props))
        _extract_embedded_edges(parsed, oid, data, kinds)
    _infer_tenant_meta(parsed)
    return parsed


def _parse_ce_file(data: dict[str, Any]) -> ParsedBloodHound:
    meta = dict(data.get("meta") or {})
    meta_type = str(meta.get("type") or "").lower()
    parsed = ParsedBloodHound(meta={"format": "ce", "ce_type": meta_type, **meta})
    rows = data.get("data") or []
    if not isinstance(rows, list):
        raise ValueError("CE payload 'data' must be an array")

    for row in rows:
        if not isinstance(row, dict):
            continue
        oid = str(row.get("ObjectIdentifier") or row.get("objectId") or row.get("id") or "")
        if not oid:
            continue
        props = dict(row.get("Properties") or row.get("properties") or {})
        kinds = _kinds_for_ce_type(meta_type, row, props)
        parsed.nodes.append(BHNode(object_id=oid, kinds=kinds, properties=props))
        _extract_embedded_edges(parsed, oid, row, kinds)

    _infer_tenant_meta(parsed)
    return parsed


def _kinds_for_ce_type(meta_type: str, row: dict[str, Any], props: dict[str, Any]) -> list[str]:
    explicit = row.get("kinds") or props.get("kinds")
    if isinstance(explicit, list) and explicit:
        return [str(k) for k in explicit]

    mapping = {
        "users": ["User"],
        "groups": ["Group"],
        "computers": ["Computer"],
        "domains": ["Domain"],
        "ous": ["OU"],
        "gpos": ["GPO"],
        "containers": ["Container"],
        "azusers": ["AZUser"],
        "azgroups": ["AZGroup"],
        "azserviceprincipals": ["AZServicePrincipal"],
        "azapplications": ["AZApp"],
        "azdevices": ["AZDevice"],
        "aztenants": ["AZTenant"],
        "azkeyvaults": ["AZKeyVault"],
        "azvms": ["AZVM"],
        "azmanagementgroups": ["AZManagementGroup"],
        "azroles": ["AZRole"],
        "azmanagedidentities": ["AZManagedIdentity"],
    }
    if meta_type in mapping:
        return list(mapping[meta_type])
    # AzureHound sometimes uses singular / camel types.
    for key, kinds in mapping.items():
        if meta_type.rstrip("s") == key.rstrip("s"):
            return list(kinds)
    if props.get("objectid") or row.get("ObjectIdentifier", "").startswith("S-1-"):
        return ["User"] if "samaccountname" in {k.lower() for k in props} else ["Base"]
    return ["AZBase"]


def _extract_embedded_edges(
    parsed: ParsedBloodHound,
    oid: str,
    row: dict[str, Any],
    kinds: list[str],
) -> None:
    # Group membership
    for member in row.get("Members") or []:
        mid = _typed_principal_id(member)
        if mid:
            parsed.edges.append(BHEdge(kind="MemberOf", start=mid, end=oid))
    for group in row.get("MemberOf") or []:
        gid = _typed_principal_id(group)
        if gid:
            parsed.edges.append(BHEdge(kind="MemberOf", start=oid, end=gid))

    # Local admin / RDP / PSRemoting → AdminTo / CanRDP / CanPSRemote
    for field_name, kind in (
        ("LocalAdmins", "AdminTo"),
        ("RemoteDesktopUsers", "CanRDP"),
        ("PSRemoteUsers", "CanPSRemote"),
        ("DcomUsers", "AdminTo"),
    ):
        for principal in row.get(field_name) or []:
            pid = _typed_principal_id(principal)
            if pid:
                parsed.edges.append(BHEdge(kind=kind, start=pid, end=oid))

    # Sessions: computer HasSession user
    for session in row.get("Sessions") or row.get("RegistrySessions") or []:
        if not isinstance(session, dict):
            continue
        user_sid = str(session.get("UserSID") or session.get("userSid") or session.get("UserId") or "")
        computer_sid = str(
            session.get("ComputerSID") or session.get("computerSid") or session.get("ComputerId") or oid
        )
        if user_sid and computer_sid:
            parsed.edges.append(BHEdge(kind="HasSession", start=computer_sid, end=user_sid))

    # ACEs
    getchanges_pairs: set[tuple[str, str]] = set()
    getchanges_all: set[tuple[str, str]] = set()
    for ace in row.get("Aces") or row.get("aces") or []:
        if not isinstance(ace, dict):
            continue
        principal = str(
            ace.get("PrincipalSID")
            or ace.get("PrincipalId")
            or ace.get("principal")
            or ""
        )
        right = str(ace.get("RightName") or ace.get("rightName") or ace.get("Right") or "")
        if not principal or not right:
            continue
        mapped = ACE_RIGHT_TO_KIND.get(right.lower())
        if not mapped:
            continue
        if mapped == "GetChanges":
            getchanges_pairs.add((principal, oid))
            continue
        if mapped == "GetChangesAll":
            getchanges_all.add((principal, oid))
            continue
        parsed.edges.append(BHEdge(kind=mapped, start=principal, end=oid, properties={"isacl": True}))

    for pair in getchanges_pairs & getchanges_all:
        parsed.edges.append(BHEdge(kind="DCSync", start=pair[0], end=pair[1], properties={"isacl": True}))
    for pair in getchanges_all - getchanges_pairs:
        # GetChangesAll alone is still a strong signal in lab corpora.
        parsed.edges.append(BHEdge(kind="DCSync", start=pair[0], end=pair[1], properties={"isacl": True}))

    # Azure-ish embedded links
    for owner in row.get("Owners") or []:
        oid_owner = _typed_principal_id(owner)
        if oid_owner:
            parsed.edges.append(BHEdge(kind="AZOwns", start=oid_owner, end=oid))
    for user_oid in row.get("Users") or []:  # group members (azure)
        mid = _typed_principal_id(user_oid)
        if mid:
            parsed.edges.append(BHEdge(kind="AZMemberOf", start=mid, end=oid))

    # Synced identity hints on AZ users
    onprem = row.get("OnPremisesSecurityIdentifier") or (row.get("Properties") or {}).get(
        "onpremisessecurityidentifier"
    )
    if onprem and any(str(k).upper().startswith("AZ") for k in kinds):
        parsed.edges.append(BHEdge(kind="SyncedToADUser", start=oid, end=str(onprem)))


def _typed_principal_id(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(
            value.get("ObjectIdentifier")
            or value.get("ObjectId")
            or value.get("objectId")
            or value.get("id")
            or value.get("value")
            or ""
        )
    return str(value)


def _infer_tenant_meta(parsed: ParsedBloodHound) -> None:
    for node in parsed.nodes:
        props = node.properties
        for key in ("tenantid", "tenant-id", "tenantId", "aztenantid"):
            if props.get(key):
                parsed.meta.setdefault("tenant_id", str(props[key]))
        if any("tenant" in str(k).lower() for k in node.kinds):
            parsed.meta.setdefault("tenant_id", node.object_id)
        domain = props.get("domain") or props.get("domainname")
        if domain:
            parsed.meta.setdefault("domain", str(domain))
    if "tenant_id" not in parsed.meta:
        for edge in parsed.edges:
            if edge.kind.upper().startswith("AZ"):
                parsed.meta.setdefault("tenant_id", "unknown")
                break
