/* Samoyed graph UI */

const state = {
  sessionId: null,
  sessionMeta: null,
  graph: { nodes: [], edges: [] },
  network: null,
  nodesDS: null,
  edgesDS: null,
  selectedNodeId: null,
  generatedPaths: null,
  graphViewSwapped: false,
  pathNetwork: null,
  pathNodesDS: null,
  pathEdgesDS: null,
  callerNodeId: null,
  nodePositions: {},
  layoutRootId: null,
  sessionListScope: "recent",
  sessionSelectionIds: null,
  markings: null,
  contextMenuNodeId: null,
  ignoredNodeIds: new Set(),
  lastPathQuery: null,
  enrichBusy: false,
  // Full SG-lite / internet CAN_REACH render. Peering (VPC_PEERS / BRIDGES_TO)
  // stays visible even when this is off — those edges are rare and high-signal.
  showNetworkEdges: false,
  showAllResourceAccess: false,
};

const NODE_COLORS = {
  Principal: { background: "#1f6feb", border: "#58a6ff", highlight: { background: "#388bfd", border: "#79c0ff" } },
  Resource: { background: "#8b2520", border: "#f85149", highlight: { background: "#b62324", border: "#ff7b72" } },
  ComputeContext: { background: "#1a4d2e", border: "#3fb950", highlight: { background: "#238636", border: "#56d364" } },
  ScopeBoundary: { background: "#30363d", border: "#8b949e", highlight: { background: "#484f58", border: "#b1bac4" } },
  PolicyStatement: { background: "#5a3c00", border: "#ffa657", highlight: { background: "#7d4e00", border: "#ffc078" } },
  AttackOutcome: { background: "#7a3a08", border: "#ffa657", highlight: { background: "#9e4b0e", border: "#ffc078" } },
  Unknown: { background: "#21262d", border: "#484f58", highlight: { background: "#30363d", border: "#8b949e" } },
};

const PATH_NODE_COLOR = { background: "#9e6a03", border: "#ffa657" };
const PATH_EDGE_COLOR = { color: "#ffa657", highlight: "#ffc078" };
const ENRICHMENT_EDGE_COLOR = { color: "#3fb9b0", highlight: "#56d4dd", hover: "#7ee8df" };
const DEFAULT_EDGE_COLOR = { color: "#484f58", highlight: "#58a6ff", hover: "#8b949e" };
const ATTACK_EDGE_COLOR = { color: "#ffa657", highlight: "#ffc078", hover: "#ffbc66" };
const SELECTED_NODE_COLOR = { background: "#388bfd", border: "#79c0ff" };
const COMPROMISED_NODE_COLOR = {
  background: "#3d1518",
  border: "#f85149",
  highlight: { background: "#5a1f24", border: "#ff7b72" },
};
const HIGH_VALUE_NODE_COLOR = {
  background: "#3d2a00",
  border: "#ffa657",
  highlight: { background: "#5a3c00", border: "#ffc078" },
};
const SHADOW_ADMIN_NODE_COLOR = {
  background: "#2a1f4a",
  border: "#a371f7",
  highlight: { background: "#3d2d6b", border: "#d2a8ff" },
};
const BOTH_MARKING_COLOR = {
  background: "#4a2030",
  border: "#ff7b72",
  highlight: { background: "#6a2840", border: "#ffa657" },
};

async function fetchJSON(url, opts) {
  const res = await fetch(url, { credentials: "same-origin", ...opts });
  if (res.status === 401) {
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login?next=${next}`;
    throw new Error("Not authenticated");
  }
  if (!res.ok) {
    const text = await res.text();
    let message = text || res.statusText;
    try {
      const body = JSON.parse(text);
      if (body?.detail) {
        if (typeof body.detail === "string") message = body.detail;
        else if (body.detail.error) {
          message = body.detail.hint
            ? `${body.detail.error} — ${body.detail.hint}`
            : body.detail.error;
        } else {
          message = JSON.stringify(body.detail);
        }
      }
    } catch {
      /* keep text */
    }
    throw new Error(message);
  }
  return res.json();
}

async function initAuth() {
  const status = await fetchJSON("/api/auth/status");
  const logoutBtn = document.getElementById("logoutBtn");
  if (status.auth_required) {
    logoutBtn.style.display = "inline-block";
    logoutBtn.onclick = async () => {
      await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
      window.location.href = "/login";
    };
  }
  if (status.auth_required && !status.authenticated) {
    window.location.href = "/login";
  }
}

function displayName(node) {
  if (node.native_kind === "PivotMaterial" || node.material_kind) {
    return materialDisplayName(node);
  }
  const base = node.display_name || node.native_id || node.arn || node.name || node.id;
  if (node.instance_id && !String(base).includes(node.instance_id)) {
    return `${base} (${node.instance_id})`;
  }
  return base;
}

function isWeakMaterialLabel(text, node = {}) {
  const raw = String(text || "").trim();
  if (!raw) return true;
  const low = raw.toLowerCase();
  const kind = String(node.material_kind || "");
  if (/^material:[a-z0-9_]+:[a-f0-9]+$/i.test(raw)) return true;
  if (low.includes("generic_credential_file")) return true;
  if (low === "credential file" || raw.startsWith("Credential file")) return true;
  if (/\(environment\):\s/.test(raw)) return true;
  if (/:generic_credential_file|:aws_secret_key_env|:aws_access_key_env|:database_connection_string\b/.test(raw)) {
    return true;
  }
  if (kind && (low === kind.toLowerCase() || low === kind.replace(/_/g, " ").toLowerCase())) {
    return true;
  }
  if (/^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/.test(raw)) return true;
  return false;
}

function materialDisplayName(node) {
  const candidates = [node.summary, node.display_name, node.finding, node.name];
  for (const c of candidates) {
    if (c && !isWeakMaterialLabel(c, node)) return String(c);
  }
  const finding =
    (node.finding && !isWeakMaterialLabel(node.finding, node) && node.finding)
    || humanizeMaterialKind(node.material_kind);
  const file = node.source_basename || (node.source_file ? String(node.source_file).split(/[/\\]/).pop() : "");
  const where = file
    ? (node.source_line != null ? `${file}:${node.source_line}` : file)
    : "";
  const hints = Array.isArray(node.name_hints) ? node.name_hints.filter(Boolean) : [];
  const hint = hints.find((h) => /cred|secret|rds|db|pass|mysql|endpoint/i.test(h)) || hints[0];
  const parts = [finding];
  if (where) parts.push(`in ${where}`);
  if (hint) parts.push(`→ ${hint}`);
  const rebuilt = parts.join(" ");
  return isWeakMaterialLabel(rebuilt, node) ? finding : rebuilt;
}

function humanizeMaterialKind(kind) {
  const map = {
    aws_access_key_env: "AWS access key",
    aws_secret_key_env: "AWS secret access key",
    aws_session_token_env: "AWS session token",
    azure_client_secret_env: "Azure client secret",
    gcp_service_account_json: "GCP service account key",
    kubeconfig_file: "Kubeconfig",
    k8s_service_account_token: "Kubernetes SA token",
    k8s_client_cert: "Kubernetes client certificate",
    database_connection_string: "Database credential",
    generic_credential_file: "Hardcoded credential",
    none_observed: "No credentials observed",
  };
  if (!kind) return "Credential material";
  return map[kind] || String(kind).replace(/_/g, " ");
}

function shortId(id) {
  if (!id) return "";
  if (id.length <= 36) return id;
  // Don't ARN-truncate human labels ("Hardcoded password in main.tf:42").
  if (/\s/.test(id) || id.includes("/") || id.includes(" in ") || id.includes(" → ")) return id;
  // Never surface material:kind:hash digests as labels.
  if (/^material:[a-z0-9_]+:[a-f0-9]+$/i.test(id) || /generic_credential_file:[a-f0-9]+/i.test(id)) {
    const parts = id.split(":");
    return humanizeMaterialKind(parts[1] || parts[0]);
  }
  const parts = id.split(":");
  return parts.length > 2 ? parts.slice(-2).join(":") : id.slice(0, 32) + "…";
}

function wrapGraphLabel(text, width = 24) {
  const raw = String(text || "");
  if (raw.length <= width) return raw;
  const parts = [];
  let remaining = raw;
  while (remaining.length > width) {
    let breakAt = remaining.lastIndexOf("/", width);
    if (breakAt < width / 3) breakAt = remaining.lastIndexOf(":", width);
    if (breakAt < width / 3) breakAt = width;
    parts.push(remaining.slice(0, breakAt));
    remaining = remaining.slice(breakAt).replace(/^[/:]/, "");
  }
  if (remaining) parts.push(remaining);
  return parts.slice(0, 3).join("\n") + (parts.length > 3 ? "…" : "");
}

function nodeColor(label) {
  return NODE_COLORS[label] || NODE_COLORS.Unknown;
}

function nodeMarkingColor(node) {
  const compromised = !!node.is_compromised;
  const highValue = !!node.is_high_value;
  const shadow = !!node.is_shadow_admin;
  if (compromised && highValue) return BOTH_MARKING_COLOR;
  if (compromised) return COMPROMISED_NODE_COLOR;
  if (highValue) return HIGH_VALUE_NODE_COLOR;
  if (shadow) return SHADOW_ADMIN_NODE_COLOR;
  return nodeColor(node.label || "Unknown");
}

function ignoredStorageKey(sessionId) {
  return `samoyed:ignoredNodes:${sessionId}`;
}

function loadIgnoredForSession(sessionId) {
  state.ignoredNodeIds = new Set();
  if (!sessionId) return;
  try {
    const raw = sessionStorage.getItem(ignoredStorageKey(sessionId));
    if (!raw) return;
    const ids = JSON.parse(raw);
    if (Array.isArray(ids)) state.ignoredNodeIds = new Set(ids.filter(Boolean));
  } catch (_) {
    /* ignore corrupt storage */
  }
}

function persistIgnoredNodes() {
  if (!state.sessionId) return;
  try {
    sessionStorage.setItem(
      ignoredStorageKey(state.sessionId),
      JSON.stringify([...state.ignoredNodeIds]),
    );
  } catch (_) {
    /* quota / private mode */
  }
}

function excludedNodeIdsPayload() {
  const ids = [...state.ignoredNodeIds];
  return ids.length ? ids : null;
}

function renderIgnoredChips() {
  const el = document.getElementById("ignoredSummary");
  if (!el) return;
  if (!state.ignoredNodeIds.size) {
    el.innerHTML = `<span class="empty">Right-click a node → Ignore from queries</span>`;
    return;
  }
  const chips = [...state.ignoredNodeIds]
    .map((id) => {
      const raw = state.graph.nodes.find((n) => n.id === id);
      const label = escapeHtml(shortId(raw ? displayName(raw) : id));
      return `<button type="button" class="marking-chip ignored" data-unignore="${escapeAttr(id)}" title="Click to stop ignoring">${label} ×</button>`;
    })
    .join("");
  el.innerHTML =
    chips +
    `<button type="button" class="ghost" id="clearAllIgnored" style="margin-left:4px;font-size:11px">Clear all</button>`;
  el.querySelectorAll("[data-unignore]").forEach((btn) => {
    btn.onclick = () => setNodeIgnored(btn.getAttribute("data-unignore"), false);
  });
  document.getElementById("clearAllIgnored")?.addEventListener("click", () => {
    state.ignoredNodeIds.clear();
    persistIgnoredNodes();
    refreshIgnoredVisuals();
  });
}

function refreshIgnoredVisuals() {
  if (state.nodesDS && state.graph?.nodes?.length) {
    const { nodes: visibleNodes } = normalizeGraphForDisplay(state.graph);
    state.nodesDS.update(visibleNodes.map((node) => toVisNode(node, state.nodePositions[node.id])));
    if (state.selectedNodeId) refreshMainGraphSelection();
  }
  renderIgnoredChips();
}

function setNodeIgnored(nodeId, ignored) {
  if (!nodeId) return;
  if (ignored) state.ignoredNodeIds.add(nodeId);
  else state.ignoredNodeIds.delete(nodeId);
  persistIgnoredNodes();
  refreshIgnoredVisuals();
}

function toVisNode(node, position) {
  const label = node.label || "Unknown";
  const colors = nodeMarkingColor(node);
  const titleParts = [
    displayName(node),
    `Label: ${label}`,
    `Concept: ${node.concept_type || "—"}`,
    node.finding ? `Finding: ${node.finding}` : null,
    node.source_file
      ? `File: ${node.source_file}${node.source_line != null ? `:${node.source_line}` : ""}`
      : null,
    node.match_preview ? `Match: ${node.match_preview}` : null,
    node.description || null,
    node.material_kind ? `Kind: ${node.material_kind}` : null,
    `ID: ${node.id}`,
    node.native_id ? `Native: ${node.native_id}` : null,
  ];
  if (node.is_compromised) titleParts.push("⚠ Marked compromised");
  if (node.is_high_value) titleParts.push("★ Marked high-value");
  if (node.is_shadow_admin) {
    titleParts.push(`◉ Shadow admin — ${node.shadow_admin_reason || node.shadow_admin_mechanism || "can escalate to admin"}`);
  }
  if (state.ignoredNodeIds.has(node.id)) titleParts.push("⊘ Ignored from queries");
  const title = titleParts.filter(Boolean).join("\n");

  const labelText = (node.native_kind === "PivotMaterial" || node.material_kind)
    ? wrapGraphLabel(displayName(node), 28)
    : wrapGraphLabel(shortId(displayName(node)));

  const ignored = state.ignoredNodeIds.has(node.id);
  const visNode = {
    id: node.id,
    label: labelText,
    title,
    group: label,
    color: { ...colors },
    font: { color: ignored ? "#8b949e" : "#e6edf3", size: 12, multi: true, align: "center" },
    shape: label === "Principal" ? "dot" : "box",
    size: label === "Principal" ? 18 : undefined,
    margin: 10,
    opacity: ignored ? 0.35 : 1,
    _raw: node,
  };

  if (position) {
    visNode.x = position.x;
    visNode.y = position.y;
  }
  return visNode;
}

function isAttackOutcomeNode(node) {
  return node?.concept_type === "AttackOutcome" || node?.label === "AttackOutcome";
}

function isPolicyStatementNode(node) {
  return (
    node?.label === "PolicyStatement"
    || node?.concept_type === "Entitlement"
    || node?.native_kind === "PolicyStatement"
  );
}

function isTrustNode(node) {
  return node?.label === "Trust" || node?.concept_type === "Trust";
}

/** Concrete / high-value stores worth showing; IAM Describe/List stubs are not. */
const INTERESTING_DATASTORE_TYPES = new Set([
  "S3Bucket",
  "GCSBucket",
  "StorageAccount",
  "BlobContainer",
  "DynamoDBTable",
  "RdsInstance",
  "RdsCluster",
  "RedshiftCluster",
  "BigQueryDataset",
  "CosmosDB",
  "EFSFileSystem",
  "SQSQueue",
  "SNSTopic",
  "KMSKey",
  "Secret",
  "SSMParameter",
  "ECRRepository",
  "EC2Instance",
  "LambdaFunction",
  "Lambda",
]);

const INTERESTING_DATASTORE_NATIVE = /^(S3Bucket|S3|Secret|SSMParameter|ECRRepository|EC2Instance|LambdaFunction|DynamoDB|RdsInstance|RdsCluster|GCSBucket|StorageAccount|SQSQueue|SNSTopic|KMSKey):/i;

function isInterestingDataStore(node) {
  if (!node) return false;
  if (node.concept_type === "SecretStore" || node.concept_type === "RegistryStore") return true;
  if (node.concept_type !== "DataStore" && node.label !== "Resource") return false;
  if (node.is_high_value) return true;
  const rt = node.resource_type || node.native_kind;
  if (rt && INTERESTING_DATASTORE_TYPES.has(rt)) return true;
  const nid = String(node.native_id || node.id || "");
  if (INTERESTING_DATASTORE_NATIVE.test(nid)) return true;
  return /^Resource:(Secret|SSMParameter|ECRRepository|EC2Instance|LambdaFunction|S3Bucket)\b/i.test(nid);
}

/** IAM-inferred service wildcards (Logs:*, Ec2 describe stubs, …) — hide those only. */
function isMundaneResourceNode(node) {
  if (!node) return false;
  if (node.concept_type === "SecretStore" || node.concept_type === "RegistryStore") return false;
  if (node.concept_type !== "DataStore" && node.label !== "Resource") return false;
  return !isInterestingDataStore(node);
}

function isHiddenDisplayNode(node) {
  return (
    !node
    || node.label === "CollectionSession"
    || isPolicyStatementNode(node)
    || isTrustNode(node)
    || isMundaneResourceNode(node)
    // Crown-jewel AttackOutcome nodes duplicate high_value / admin markings on identities.
    || isAttackOutcomeNode(node)
  );
}

const ENRICHMENT_EDGE_SOURCES = new Set([
  "surface-enrichment",
  "pivot-enrichment",
  "enrichment",
  "host-pivot",
  "collector-enrichment",
  "network-enrichment",
]);

const ENRICHMENT_EDGE_RELS = new Set([
  "HAS_MATERIAL",
  "UNLOCKS",
  "MOUNTED_INTO",
  "REFERENCES",
  "LOGGED_IN_AS",
  "STORES_CREDS_FOR",
  "CAN_STEAL_CREDS_FROM",
]);

function isEnrichmentEdge(edge) {
  if (!edge || edge.attack_outcome) return false;
  if (edge.edge_origin === "enrichment" || edge.is_enrichment === true) return true;
  if (edge.source && ENRICHMENT_EDGE_SOURCES.has(edge.source)) return true;
  if (ENRICHMENT_EDGE_RELS.has(edge.rel)) return true;
  if (edge.rel === "CAN_ESCAPE_TO" && edge.mechanism) return true;
  if (
    edge.rel === "EXECUTES_AS"
    && (ENRICHMENT_EDGE_SOURCES.has(edge.source) || String(edge.mechanism || "").startsWith("imds"))
  ) {
    return true;
  }
  if (edge.rel === "CAN_REACH" && ENRICHMENT_EDGE_SOURCES.has(edge.source)) return true;
  if (edge.rel === "VPC_PEERS" || edge.rel === "BRIDGES_TO") return true;
  if (edge.harvest_method || edge.store_type) return true;
  return false;
}

function isPeeringNetworkEdge(edge) {
  return Boolean(edge && (edge.rel === "VPC_PEERS" || edge.rel === "BRIDGES_TO"));
}

function isNetworkEdge(edge) {
  if (!edge) return false;
  if (isPeeringNetworkEdge(edge)) return true;
  if (edge.source === "network-enrichment") return true;
  if (edge.rel === "CAN_REACH" && (edge.mechanism === "sg-lite" || edge.mechanism === "internet-ingress" || edge.mechanism === "vpc-peering")) {
    return true;
  }
  return false;
}

/** Edges gated by the "Network Edges (All)" toggle — peering is never gated. */
function isToggleableNetworkEdge(edge) {
  return isNetworkEdge(edge) && !isPeeringNetworkEdge(edge);
}

function edgeVisStyle(edge) {
  if (edge.attack_outcome || edge._raw?.attack_outcome) {
    return {
      color: ATTACK_EDGE_COLOR,
      fontColor: "#ffa657",
      width: 2.5,
      fontSize: 12,
    };
  }
  if (isEnrichmentEdge(edge)) {
    return {
      color: ENRICHMENT_EDGE_COLOR,
      fontColor: "#56d4dd",
      width: 2,
      fontSize: 10,
    };
  }
  return {
    color: DEFAULT_EDGE_COLOR,
    fontColor: "#8b949e",
    width: 1.5,
    fontSize: 9,
  };
}

const COMPACTABLE_CAPABILITY_RELS = new Set([
  "READS",
  "WRITES",
  "DELETES",
  "CONTROLS",
  "EXECUTES",
]);

const CAPABILITY_REL_STRENGTH = {
  CONTROLS: 50,
  WRITES: 40,
  DELETES: 35,
  EXECUTES: 30,
  READS: 10,
};

function compactCapabilityEdges(edges) {
  const kept = [];
  const buckets = new Map();
  const privescPairs = new Set();

  for (const edge of edges) {
    if (edge.rel === "CAN_PRIVESC_TO") {
      const blob = `${edge.pattern_id || ""} ${edge.pattern_name || ""}`.toLowerCase();
      const assumeLike = ["passrole", "assume-role", "assumerole", "update-assume", "create-access-key"]
        .some((tok) => blob.includes(tok));
      if (assumeLike) privescPairs.add(`${edge.src}\0${edge.dst}`);
    }
  }

  for (const edge of edges) {
    // Assume is redundant when privesc already covers the same endpoints.
    if (edge.rel === "CAN_ASSUME_ROLE" && privescPairs.has(`${edge.src}\0${edge.dst}`)) {
      continue;
    }
    // PassRole CONTROLS → Identity is redundant with CAN_PRIVESC_TO → that Identity.
    if (
      (edge.rel === "CONTROLS" || edge.rel === "EXECUTES")
      && privescPairs.has(`${edge.src}\0${edge.dst}`)
      && !["iam:*", "*"].includes(String(edge.action || "").toLowerCase())
    ) {
      const dstConcept = edge._dstConcept || edge.dst_concept_type;
      // Without concept on the edge, still drop CONTROLS when destination is a Principal id.
      if (
        dstConcept === "Identity"
        || String(edge.dst || "").startsWith("Principal:")
      ) {
        continue;
      }
    }
    if (
      !COMPACTABLE_CAPABILITY_RELS.has(edge.rel)
      || edge.attack_outcome
      || edge._collapsedOutcome
      || isEnrichmentEdge(edge)
    ) {
      kept.push(edge);
      continue;
    }
    const key = `${edge.src}\0${edge.dst}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(edge);
  }

  for (const group of buckets.values()) {
    if (group.length === 1) {
      kept.push(group[0]);
      continue;
    }
    const rels = [...new Set(group.map((edge) => edge.rel))].sort(
      (a, b) => (CAPABILITY_REL_STRENGTH[b] || 0) - (CAPABILITY_REL_STRENGTH[a] || 0),
    );
    const primary = group
      .slice()
      .sort(
        (a, b) => (CAPABILITY_REL_STRENGTH[b.rel] || 0) - (CAPABILITY_REL_STRENGTH[a.rel] || 0),
      )[0];
    const actions = [
      ...new Set(group.map((edge) => edge.action).filter(Boolean)),
    ].sort();
    kept.push({
      ...primary,
      rel: rels[0],
      _mergedRels: rels,
      _mergedCount: group.length,
      _mergedActions: actions,
      _compactLabel: rels.length === 1 ? rels[0] : rels.join(" · "),
    });
  }

  return kept;
}

const RESOURCE_ACCESS_RELS = new Set([
  "READS",
  "WRITES",
  "DELETES",
  "CONTROLS",
  "EXECUTES",
  "CAN_ACCESS",
]);

function isPrivescOutcomeEdge(edge, outcomeIds) {
  return (
    edge?.rel === "CAN_PRIVESC_TO"
    && (Boolean(edge.attack_outcome) || outcomeIds.has(edge.dst))
  );
}

function leafResourceAccessNodeIds(nodes, edges, outcomeIds) {
  const visibleIds = new Set(nodes.map((node) => node.id));
  const incoming = new Map(nodes.map((node) => [node.id, []]));
  const hasChildren = new Set();
  const hasPrivescOutcome = new Set();

  for (const edge of edges) {
    if (edge.rel === "DISCOVERED") continue;
    if (!visibleIds.has(edge.src) || !visibleIds.has(edge.dst)) continue;
    incoming.get(edge.dst)?.push(edge);
    if (edge.src !== edge.dst) hasChildren.add(edge.src);
    if (isPrivescOutcomeEdge(edge, outcomeIds)) hasPrivescOutcome.add(edge.src);
  }

  return new Set(
    nodes
      .filter((node) => {
        if (node.label !== "Resource") return false;
        if (node.is_caller || node.compromised || node.high_value) return false;
        if (hasChildren.has(node.id) || hasPrivescOutcome.has(node.id)) return false;
        const accessEdges = incoming.get(node.id) || [];
        return (
          accessEdges.length > 0
          && accessEdges.every((edge) => RESOURCE_ACCESS_RELS.has(edge.rel))
        );
      })
      .map((node) => node.id),
  );
}

function normalizeGraphForDisplay(graph) {
  const outcomeIds = new Set(
    (graph.nodes || []).filter(isAttackOutcomeNode).map((n) => n.id),
  );
  let nodes = (graph.nodes || []).filter((n) => !isHiddenDisplayNode(n));
  if (!state.showAllResourceAccess) {
    const hiddenLeafIds = leafResourceAccessNodeIds(
      nodes,
      graph.edges || [],
      outcomeIds,
    );
    nodes = nodes.filter((node) => !hiddenLeafIds.has(node.id));
  }
  const nodeIds = new Set(nodes.map((n) => n.id));
  const edges = [];

  for (const edge of graph.edges || []) {
    if (edge.rel === "DISCOVERED") continue;
    if (!state.showNetworkEdges && isToggleableNetworkEdge(edge)) continue;
    // Never draw CAN_PRIVESC_TO as a self-loop. AttackOutcome destinations are
    // already hidden display nodes; collapsing those edges onto the principal
    // produced the orange "points at itself" loops. Drop them instead.
    if (edge.rel === "CAN_PRIVESC_TO" && (edge.src === edge.dst || isPrivescOutcomeEdge(edge, outcomeIds))) {
      continue;
    }
    if (nodeIds.has(edge.src) && nodeIds.has(edge.dst)) {
      edges.push(edge);
    }
  }

  return { nodes, edges: compactCapabilityEdges(edges) };
}

function edgeDisplayLabel(edge) {
  if (edge._compactLabel) return edge._compactLabel;
  if (edge.rel === "BRIDGES_TO" || edge.ui_label === "" || edge.boundary_crossing) {
    return "";
  }
  if (edge.attack_outcome) {
    return `👑 ${edge.rel}`;
  }
  // Escapes are transitive edges — show which technique enables the escape.
  if (edge.rel === "CAN_ESCAPE_TO" && edge.mechanism) {
    return `◇ ${edge.rel} (${edge.mechanism})`;
  }
  if (isEnrichmentEdge(edge)) {
    return `◇ ${edge.rel}`;
  }
  return edge.rel;
}

function graphNodeMap(nodes) {
  return new Map(nodes.map((n) => [n.id, n]));
}

function formatEdgeHint(edge, nodeById) {
  const src = nodeById.get(edge.src);
  const dst = nodeById.get(edge.dst);
  const srcLabel = src ? `${src.label}: ${displayName(src)}` : edge.src;
  const dstLabel = dst ? `${dst.label}: ${displayName(dst)}` : edge.dst;
  const head = edge._compactLabel || edge.rel;
  const lines = edge.attack_outcome
    ? [
        `👑 ${edge.outcome_display || edge.attack_outcome}`,
        edge.pattern_name ? `via ${edge.pattern_name}` : null,
        edge.src === edge.dst ? shortId(srcLabel) : `${shortId(srcLabel)} → ${shortId(dstLabel)}`,
      ].filter(Boolean)
    : [head, `${shortId(srcLabel)} → ${shortId(dstLabel)}`];

  if (edge._mergedCount > 1) {
    lines.push(`merged ${edge._mergedCount} capability edges`);
    if (edge._mergedRels?.length) lines.push(`relations: ${edge._mergedRels.join(", ")}`);
  }

  const meta = [];
  if (edge.confidence) meta.push(`confidence: ${edge.confidence}`);
  if (edge._mergedActions?.length) {
    const shown = edge._mergedActions.slice(0, 8);
    meta.push(
      `actions: ${shown.join(", ")}${edge._mergedActions.length > 8 ? ` (+${edge._mergedActions.length - 8})` : ""}`,
    );
  } else if (edge.action) {
    meta.push(`action: ${edge.action}`);
  }
  if (edge.source) meta.push(`source: ${edge.source}`);
  if (edge.edge_origin === "enrichment" || isEnrichmentEdge(edge)) meta.push("derived: enrichment");
  if (edge.discovered_via) meta.push(`via: ${edge.discovered_via}`);
  if (edge.cartography_rel) meta.push(`cartography: ${edge.cartography_rel}`);
  if (edge.pattern_name) meta.push(`pattern: ${edge.pattern_name}`);
  if (edge.pattern_description) meta.push(String(edge.pattern_description));
  if (edge.pattern_id) meta.push(`pattern_id: ${edge.pattern_id}`);
  if (edge.required_actions?.length) meta.push(`requires: ${edge.required_actions.join(", ")}`);
  if (edge.mitre_technique_ids?.length) {
    meta.push(`MITRE: ${edge.mitre_technique_ids.join(", ")}`);
  }
  if (meta.length) lines.push(meta.join(" · "));

  return lines.join("\n");
}

function estimateNodeFootprint(node) {
  const wrapped = wrapGraphLabel(shortId(displayName(node || {})));
  const lines = wrapped.split("\n");
  const longest = Math.max(...lines.map((line) => line.length), 4);
  const isPrincipal = (node?.label || "") === "Principal";
  return {
    width: isPrincipal ? 56 : Math.min(240, 40 + longest * 7),
    height: isPrincipal ? 42 : 24 + lines.length * 16,
  };
}

function buildAdjacency(nodes, edges) {
  const idSet = new Set(nodes.map((n) => n.id));
  const outgoing = new Map();
  const undirected = new Map();
  idSet.forEach((id) => {
    outgoing.set(id, []);
    undirected.set(id, []);
  });
  edges.forEach((edge) => {
    if (!idSet.has(edge.src) || !idSet.has(edge.dst) || edge.src === edge.dst) return;
    outgoing.get(edge.src).push(edge.dst);
    undirected.get(edge.src).push(edge.dst);
    undirected.get(edge.dst).push(edge.src);
  });
  return { outgoing, undirected, idSet };
}

function pickLayoutRoots(nodes, rootId, idSet) {
  const roots = [];
  if (rootId && idSet.has(rootId)) roots.push(rootId);
  nodes.forEach((node) => {
    if (!idSet.has(node.id) || roots.includes(node.id)) return;
    if (node.is_caller || node.is_scenario_start || node.is_compromised) roots.push(node.id);
  });
  if (!roots.length && nodes.length) {
    const principals = nodes.filter((n) => n.label === "Principal" || n.concept_type === "Identity");
    roots.push((principals[0] || nodes[0]).id);
  }
  return roots;
}

function findConnectedComponents(nodes, undirected) {
  const seen = new Set();
  const components = [];
  for (const node of nodes) {
    if (seen.has(node.id)) continue;
    const ids = [];
    const queue = [node.id];
    seen.add(node.id);
    while (queue.length) {
      const id = queue.shift();
      ids.push(id);
      for (const nbr of undirected.get(id) || []) {
        if (seen.has(nbr)) continue;
        seen.add(nbr);
        queue.push(nbr);
      }
    }
    components.push(ids);
  }
  return components;
}

function scoreLayoutComponent(ids, nodeById, preferredRoot) {
  let score = ids.length * 10;
  for (const id of ids) {
    const node = nodeById.get(id);
    if (!node) continue;
    if (id === preferredRoot) score += 10000;
    if (node.is_caller || node.is_scenario_start) score += 5000;
    if (node.is_compromised) score += 800;
    if (node.is_high_value) score += 300;
    if (node.is_shadow_admin) score += 220;
    if (node.label === "Principal" || node.concept_type === "Identity") score += 25;
    if (node.concept_type === "SecretStore" || node.concept_type === "RegistryStore") score += 40;
  }
  return score;
}

function assignLayoutLevels(nodes, edges, rootId) {
  const { outgoing, undirected, idSet } = buildAdjacency(nodes, edges);
  const levels = new Map();
  const roots = pickLayoutRoots(nodes, rootId, idSet);
  const queue = [...roots];
  roots.forEach((id) => levels.set(id, 0));

  // Prefer attack-direction (outgoing) BFS from roots.
  while (queue.length) {
    const id = queue.shift();
    const level = levels.get(id) ?? 0;
    for (const dst of outgoing.get(id) || []) {
      const next = level + 1;
      if (!levels.has(dst) || levels.get(dst) > next) {
        levels.set(dst, next);
        queue.push(dst);
      }
    }
  }

  // Pull remaining connected nodes near already-placed neighbors (avoids one-node-per-column lines).
  let progressed = true;
  while (progressed) {
    progressed = false;
    for (const node of nodes) {
      if (levels.has(node.id)) continue;
      const neighborLevels = (undirected.get(node.id) || [])
        .map((nid) => levels.get(nid))
        .filter((value) => value !== undefined);
      if (!neighborLevels.length) continue;
      levels.set(node.id, Math.min(...neighborLevels) + 1);
      progressed = true;
    }
  }

  // Any leftovers (shouldn't happen inside one component) get a tight local BFS pack.
  const unplaced = nodes.map((n) => n.id).filter((id) => !levels.has(id));
  if (unplaced.length) {
    const local = new Map([[unplaced[0], 0]]);
    const lq = [unplaced[0]];
    while (lq.length) {
      const id = lq.shift();
      for (const nbr of undirected.get(id) || []) {
        if (!unplaced.includes(nbr) || local.has(nbr)) continue;
        local.set(nbr, (local.get(id) || 0) + 1);
        lq.push(nbr);
      }
    }
    const base = (levels.size ? Math.max(...levels.values()) : -1) + 1;
    unplaced.forEach((id) => levels.set(id, base + (local.get(id) || 0)));
  }

  return { levels, roots };
}

function orderLayerByBarycenter(layerIds, prevPositions, undirected) {
  if (!prevPositions || !prevPositions.size) {
    return layerIds.slice().sort();
  }
  return layerIds
    .slice()
    .sort((a, b) => {
      const bary = (id) => {
        const nbrs = (undirected.get(id) || []).filter((n) => prevPositions.has(n));
        if (!nbrs.length) return prevPositions.has(id) ? prevPositions.get(id) : Number.POSITIVE_INFINITY;
        return nbrs.reduce((sum, n) => sum + prevPositions.get(n), 0) / nbrs.length;
      };
      const diff = bary(a) - bary(b);
      if (Number.isFinite(diff) && diff !== 0) return diff;
      return String(a).localeCompare(String(b));
    });
}

function layoutConnectedComponent(nodes, edges, rootId) {
  if (!nodes.length) {
    return { positions: {}, width: 0, height: 0, minX: 0, minY: 0 };
  }

  const nodeById = graphNodeMap(nodes);
  const { undirected } = buildAdjacency(nodes, edges);
  const { levels } = assignLayoutLevels(nodes, edges, rootId);

  const byLevel = new Map();
  levels.forEach((level, id) => {
    if (!byLevel.has(level)) byLevel.set(level, []);
    byLevel.get(level).push(id);
  });

  const orderedLevels = [...byLevel.keys()].sort((a, b) => a - b);
  const levelOrder = new Map();
  let prevY = new Map();

  for (let pass = 0; pass < 3; pass += 1) {
    const nextPrev = new Map();
    orderedLevels.forEach((level) => {
      const ordered = orderLayerByBarycenter(byLevel.get(level), prevY, undirected);
      levelOrder.set(level, ordered);
      ordered.forEach((id, index) => nextPrev.set(id, index));
    });
    prevY = nextPrev;
  }

  const positions = {};
  let cursorX = 0;
  const minXGap = 220;
  const minYGap = 88;
  // Prefer taller columns so attack depth stays compact left→right.
  const maxColumnHeight = Math.max(8, Math.ceil(Math.sqrt(nodes.length) * 1.6));

  orderedLevels.forEach((level) => {
    const ids = levelOrder.get(level) || byLevel.get(level);
    const columns = [];
    for (let i = 0; i < ids.length; i += maxColumnHeight) {
      columns.push(ids.slice(i, i + maxColumnHeight));
    }

    let levelWidth = 0;
    let levelHeight = 0;
    columns.forEach((columnIds, colIndex) => {
      const colFeet = columnIds.map((id) => estimateNodeFootprint(nodeById.get(id)));
      const colWidth = Math.max(72, ...colFeet.map((f) => f.width));
      const gaps = colFeet.map((foot) => Math.max(minYGap, foot.height + 28));
      const stackHeight = gaps.reduce((sum, gap, index) => (
        index === gaps.length - 1 ? sum + colFeet[index].height : sum + gap
      ), 0);
      const center = stackHeight / 2;
      let y = 0;
      const x = cursorX + colIndex * (colWidth + 48);
      columnIds.forEach((id, index) => {
        positions[id] = { x, y: y - center + colFeet[index].height / 2 };
        if (index < columnIds.length - 1) y += gaps[index];
      });
      levelWidth = Math.max(levelWidth, (colIndex + 1) * (colWidth + 48) - 48);
      levelHeight = Math.max(levelHeight, stackHeight);
    });

    cursorX += Math.max(levelWidth, minXGap) + 56;
  });

  const xs = Object.values(positions).map((p) => p.x);
  const ys = Object.values(positions).map((p) => p.y);
  const feet = nodes.map((n) => estimateNodeFootprint(n));
  const maxHalfW = Math.max(40, ...feet.map((f) => f.width / 2));
  const maxHalfH = Math.max(20, ...feet.map((f) => f.height / 2));
  const minX = Math.min(...xs) - maxHalfW;
  const maxX = Math.max(...xs) + maxHalfW;
  const minY = Math.min(...ys) - maxHalfH;
  const maxY = Math.max(...ys) + maxHalfH;

  return {
    positions,
    width: Math.max(80, maxX - minX),
    height: Math.max(60, maxY - minY),
    minX,
    minY,
  };
}

function computeLayeredLayout(nodes, edges, rootId) {
  if (!nodes.length) return {};

  const nodeById = graphNodeMap(nodes);
  const { undirected } = buildAdjacency(nodes, edges);
  const components = findConnectedComponents(nodes, undirected).sort(
    (a, b) => scoreLayoutComponent(b, nodeById, rootId) - scoreLayoutComponent(a, nodeById, rootId),
  );

  const gapX = 140;
  const gapY = 160;
  const layouts = components.map((ids) => {
    const idSet = new Set(ids);
    const componentNodes = ids.map((id) => nodeById.get(id)).filter(Boolean);
    const componentEdges = edges.filter((edge) => idSet.has(edge.src) && idSet.has(edge.dst));
    const localRoot = ids.includes(rootId)
      ? rootId
      : pickLayoutRoots(componentNodes, null, idSet)[0];
    return layoutConnectedComponent(componentNodes, componentEdges, localRoot);
  });

  // Soft viewport budget: keep primary attack-path band readable, wrap extras beside/below.
  const primaryWidth = layouts[0]?.width || 720;
  const maxRowWidth = Math.max(primaryWidth * 1.35, 980);

  const positions = {};
  let rowX = 0;
  let rowY = 0;
  let rowHeight = 0;

  layouts.forEach((layout, index) => {
    if (index > 0 && rowX > 0 && rowX + layout.width > maxRowWidth) {
      rowX = 0;
      rowY += rowHeight + gapY;
      rowHeight = 0;
    }

    Object.entries(layout.positions).forEach(([id, point]) => {
      positions[id] = {
        x: point.x - layout.minX + rowX,
        y: point.y - layout.minY + rowY,
      };
    });

    rowX += layout.width + gapX;
    rowHeight = Math.max(rowHeight, layout.height);
  });

  return positions;
}

function visEdgeId(edge, idCounts) {
  let base = `${edge.src}|${edge.rel}|${edge.dst}`;
  if (edge.pattern_id) base += `|${edge.pattern_id}`;
  else if (edge.action) base += `|${edge.action}`;
  // Escape edges render as parallel edges — one per technique to the same host.
  else if (edge.rel === "CAN_ESCAPE_TO" && edge.mechanism) base += `|${edge.mechanism}`;
  const seen = idCounts.get(base) || 0;
  idCounts.set(base, seen + 1);
  return seen === 0 ? base : `${base}#${seen}`;
}

function wireEdgeInteractionHandlers(network, edgesDS) {
  network.on("hoverEdge", (params) => {
    if (!params.edge) return;
    const visEdge = edgesDS.get(params.edge);
    if (visEdge?._hideLabel) {
      edgesDS.update({ id: params.edge, label: visEdge._relLabel });
    }
    showEdgeTooltip(params.event, visEdge?._hint || visEdge?.title);
  });

  network.on("blurEdge", (params) => {
    hideEdgeTooltip();
    if (!params.edge) return;
    const visEdge = edgesDS.get(params.edge);
    if (visEdge?._hideLabel) {
      edgesDS.update({ id: params.edge, label: "" });
    }
  });

  network.on("dragStart", hideEdgeTooltip);
  network.on("zoom", hideEdgeTooltip);
}

function edgeLookupKey(src, rel, dst) {
  return `${src}|${rel}|${dst}`;
}

function buildGraphEdgeLookup(graph) {
  const lookup = new Map();
  const { edges: displayEdges } = normalizeGraphForDisplay(graph);
  for (const edge of displayEdges) {
    lookup.set(edgeLookupKey(edge.src, edge.rel, edge.dst), edge);
  }
  for (const edge of graph.edges || []) {
    const key = edgeLookupKey(edge.src, edge.rel, edge.dst);
    if (!lookup.has(key)) lookup.set(key, edge);
  }
  return lookup;
}

function resolveStepEdges(steps) {
  const lookup = buildGraphEdgeLookup(state.graph);

  return steps.map((step, index) => {
    const rel = step.rel || step.rel_type;
    let src = step.src || step.src_id;
    let dst = step.dst || step.dst_id;
    const evidence = step.evidence || {};

    // Never collapse privesc onto self — outcomes are real graph nodes now.
    if (rel === "CAN_PRIVESC_TO" && src === dst && evidence.attack_outcome) {
      const outcome = (state.graph.nodes || []).find(
        (n) => isAttackOutcomeNode(n)
          && (n.attack_outcome === evidence.attack_outcome
            || n.resource_type === evidence.attack_outcome),
      );
      if (outcome) dst = outcome.id;
    }

    let graphEdge =
      lookup.get(edgeLookupKey(src, rel, dst))
      || lookup.get(edgeLookupKey(src, rel, step.dst || step.dst_id))
      || (state.graph.edges || []).find(
        (e) => e.src === src && e.rel === rel && (e.dst === dst || e.dst === step.dst),
      );

    const merged = {
      ...(graphEdge || {}),
      src,
      dst,
      rel,
      _sourceIndex: index,
      ...evidence,
    };

    const enrichKeys = [
      "pattern_name",
      "pattern_id",
      "pattern_description",
      "attack_outcome",
      "outcome_display",
      "action",
      "confidence",
      "source",
      "edge_origin",
      "is_enrichment",
      "mechanism",
      "harvest_method",
      "store_type",
      "severity",
      "required_actions",
      "mitre_technique_ids",
    ];
    for (const key of enrichKeys) {
      if (merged[key] == null && graphEdge?.[key] != null) merged[key] = graphEdge[key];
      if (merged[key] == null && evidence[key] != null) merged[key] = evidence[key];
    }

    return merged;
  });
}

function buildPathViewEdges(stepEdges, nodeById) {
  return buildVisEdges(annotateEdgeSourceIndex(stepEdges), nodeById).map((edge) => {
    const style = edgeVisStyle(edge._raw || edge);
    return {
      ...edge,
      label: edge._hideLabel ? "" : edge._relLabel || edge.label,
      width: Math.max(edge.width || 1.5, style.width),
      font: {
        ...edge.font,
        size: Math.max(edge.font?.size || 9, style.fontSize),
        color: style.fontColor,
        strokeWidth: 0,
        align: "horizontal",
      },
      color: style.color,
    };
  });
}

function edgeMatchesStep(visEdge, step) {
  const src = step.src || step.src_id;
  const dst = step.dst || step.dst_id;
  const rel = step.rel || step.rel_type;
  return (
    visEdge.from === src
    && visEdge.to === dst
    && (visEdge._relLabel === rel || visEdge.label === rel || String(visEdge._relLabel || "").endsWith(` ${rel}`))
  );
}

function buildVisEdges(edges, nodeById) {
  // Hard ban: CAN_PRIVESC_TO must never render as a self-loop, even if a caller
  // feeds normalize output that somehow still has src === dst.
  edges = (edges || []).filter(
    (edge) => !(edge.rel === "CAN_PRIVESC_TO" && edge.src === edge.dst),
  );
  const pairCounts = new Map();
  const pairSeen = new Map();
  const sourceCounts = new Map();
  const idCounts = new Map();

  edges.forEach((edge) => {
    const pairKey = edge.src === edge.dst ? `self:${edge.src}` : `${edge.src}|${edge.dst}`;
    pairCounts.set(pairKey, (pairCounts.get(pairKey) || 0) + 1);
    sourceCounts.set(edge.src, (sourceCounts.get(edge.src) || 0) + 1);
  });

  return edges.map((edge) => {
    const hint = formatEdgeHint(edge, nodeById);
    const pairKey = edge.src === edge.dst ? `self:${edge.src}` : `${edge.src}|${edge.dst}`;
    const pairIndex = pairSeen.get(pairKey) || 0;
    pairSeen.set(pairKey, pairIndex + 1);
    const pairTotal = pairCounts.get(pairKey) || 1;
    const sourceIndex = edge._sourceIndex ?? 0;
    const sourceTotal = sourceCounts.get(edge.src) || 1;

    let smooth;
    if (edge.src === edge.dst) {
      smooth = {
        type: "curvedCW",
        roundness: 0.55,
      };
    } else if (pairTotal === 1 && sourceTotal === 1) {
      smooth = { type: "cubicBezier", forceDirection: "horizontal", roundness: 0.22 };
    } else if (pairTotal > 1) {
      const spread = pairIndex - (pairTotal - 1) / 2;
      smooth = {
        type: spread <= 0 ? "curvedCCW" : "curvedCW",
        roundness: 0.28 + Math.abs(spread) * 0.32,
      };
    } else {
      const spread = sourceIndex - (sourceTotal - 1) / 2;
      smooth = {
        type: spread % 2 === 0 ? "curvedCW" : "curvedCCW",
        roundness: 0.14 + Math.abs(spread) * 0.1,
      };
    }

    const hideLabel = pairTotal > 1 && !edge.attack_outcome && !isEnrichmentEdge(edge);
    const relLabel = edgeDisplayLabel(edge);
    const style = edgeVisStyle(edge);
    const visEdge = {
      id: visEdgeId(edge, idCounts),
      from: edge.src,
      to: edge.dst,
      label: hideLabel ? "" : relLabel,
      title: hint,
      arrows: "to",
      font: {
        align: "horizontal",
        size: style.fontSize,
        color: style.fontColor,
        strokeWidth: 0,
      },
      color: style.color,
      width: style.width,
      smooth,
      _raw: edge,
      _hint: hint,
      _relLabel: relLabel,
      _hideLabel: hideLabel,
    };

    if (edge.src === edge.dst) {
      visEdge.selfReference = {
        size: 28 + pairIndex * 8,
        angle: 250 + pairIndex * 24,
        renderBehindTheNode: false,
      };
    }

    return visEdge;
  });
}

function annotateEdgeSourceIndex(edges) {
  const sourceSeen = new Map();
  return edges.map((edge) => {
    const index = sourceSeen.get(edge.src) || 0;
    sourceSeen.set(edge.src, index + 1);
    return { ...edge, _sourceIndex: index };
  });
}

let edgeTooltipEl = null;

function ensureEdgeTooltip() {
  if (!edgeTooltipEl) {
    edgeTooltipEl = document.createElement("div");
    edgeTooltipEl.id = "edgeTooltip";
    edgeTooltipEl.className = "graph-tooltip";
    edgeTooltipEl.setAttribute("role", "tooltip");
    document.body.appendChild(edgeTooltipEl);
  }
  return edgeTooltipEl;
}

function showEdgeTooltip(event, hint) {
  if (!hint) return;
  const el = ensureEdgeTooltip();
  const [head, ...rest] = hint.split("\n");
  el.replaceChildren();
  const strong = document.createElement("strong");
  strong.textContent = head;
  el.appendChild(strong);
  rest.forEach((line) => {
    el.appendChild(document.createElement("br"));
    el.appendChild(document.createTextNode(line));
  });
  el.style.display = "block";
  positionEdgeTooltip(el, event);
}

function hideEdgeTooltip() {
  if (edgeTooltipEl) edgeTooltipEl.style.display = "none";
}

function positionEdgeTooltip(el, event) {
  const pad = 14;
  let x = event.clientX + pad;
  let y = event.clientY + pad;
  el.style.left = `${x}px`;
  el.style.top = `${y}px`;
  const rect = el.getBoundingClientRect();
  if (rect.right > window.innerWidth - 8) {
    el.style.left = `${event.clientX - rect.width - pad}px`;
  }
  if (rect.bottom > window.innerHeight - 8) {
    el.style.top = `${event.clientY - rect.height - pad}px`;
  }
}

function findScenarioStartNode(nodes) {
  return (
    nodes.find((n) => n.is_caller)?.id ||
    nodes.find((n) => n.native_kind === "CompromisedHost")?.id ||
    nodes.find((n) => n.is_scenario_start)?.id ||
    null
  );
}

function initNetwork() {
  const container = document.getElementById("graph");
  state.nodesDS = new vis.DataSet([]);
  state.edgesDS = new vis.DataSet([]);

  const options = {
    layout: {
      improvedLayout: true,
    },
    physics: {
      enabled: false,
    },
    interaction: {
      hover: true,
      hoverConnectedEdges: true,
      tooltipDelay: 80,
      multiselect: false,
    },
    edges: {
      width: 1.5,
      selectionWidth: 2.5,
      hoverWidth: 3,
    },
    nodes: {
      borderWidth: 2,
      margin: 8,
    },
  };

  state.network = new vis.Network(container, { nodes: state.nodesDS, edges: state.edgesDS }, options);

  state.network.on("click", (params) => {
    hideContextMenu();
    if (params.nodes.length) {
      setPathSearchStart(params.nodes[0]);
    }
  });

  state.network.on("doubleClick", (params) => {
    if (params.nodes.length) {
      openNodeDetail(params.nodes[0]);
    }
  });

  wireEdgeInteractionHandlers(state.network, state.edgesDS);

  window.addEventListener("resize", () => {
    resizeGraphNetworks();
  });

  initContextMenu();
  initEnrichmentUpload();
  initPathGraph();
  initPanelResizer();
  restoreGraphViewPreference();
}

function isGraphOnMain() {
  const mainHost = document.getElementById("mainGraphHost");
  return mainHost?.contains(document.getElementById("graph")) ?? true;
}

function getMainViewportNetwork() {
  return isGraphOnMain() ? state.network : state.pathNetwork;
}

function getMiniViewportNetwork() {
  return isGraphOnMain() ? state.pathNetwork : state.network;
}

function updateGraphViewLabels() {
  const onMain = isGraphOnMain();
  const mainLabel = document.getElementById("mainGraphLabel");
  const miniLabel = document.getElementById("miniGraphLabel");
  if (mainLabel) mainLabel.textContent = onMain ? "Full graph" : "Generated graph";
  if (miniLabel) miniLabel.textContent = onMain ? "Generated graph" : "Full graph";
}

function resizeNetworkToContainer(network, containerEl) {
  if (!network || !containerEl) return;
  const w = containerEl.clientWidth;
  const h = containerEl.clientHeight;
  if (w > 0 && h > 0) {
    network.setSize(`${w}px`, `${h}px`);
  }
  network.redraw();
}

function resizeGraphNetworks({ fitMain = false } = {}) {
  requestAnimationFrame(() => {
    const graphEl = document.getElementById("graph");
    const pathEl = document.getElementById("pathGraph");
    if (state.network && graphEl) resizeNetworkToContainer(state.network, graphEl);
    if (state.pathNetwork && pathEl) resizeNetworkToContainer(state.pathNetwork, pathEl);
    if (fitMain) {
      const mainNet = getMainViewportNetwork();
      if (mainNet && (state.nodesDS?.get()?.length || state.pathNodesDS?.get()?.length)) {
        mainNet.fit({ animation: { duration: 350, easingFunction: "easeInOutQuad" } });
      }
    }
  });
}

function refreshGraphViewports({ fit = false } = {}) {
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const graphEl = document.getElementById("graph");
      const pathEl = document.getElementById("pathGraph");
      if (state.network && graphEl) resizeNetworkToContainer(state.network, graphEl);
      if (state.pathNetwork && pathEl) resizeNetworkToContainer(state.pathNetwork, pathEl);
      if (fit) {
        const mainNet = getMainViewportNetwork();
        const mainEl = isGraphOnMain() ? graphEl : pathEl;
        if (mainNet && mainEl?.clientWidth > 0) {
          mainNet.fit({ animation: { duration: 350, easingFunction: "easeInOutQuad" } });
        }
      }
    });
  });
}

function swapGraphViews() {
  const graphEl = document.getElementById("graph");
  const pathEl = document.getElementById("pathGraph");
  const mainHost = document.getElementById("mainGraphHost");
  const miniHost = document.getElementById("miniGraphHost");
  if (!graphEl || !pathEl || !mainHost || !miniHost) return;

  const willSwap = !state.graphViewSwapped;

  if (willSwap) {
    mainHost.appendChild(pathEl);
    miniHost.appendChild(graphEl);
  } else {
    mainHost.appendChild(graphEl);
    miniHost.appendChild(pathEl);
  }

  graphEl.classList.remove("graph-canvas--large", "graph-canvas--mini");
  pathEl.classList.remove("graph-canvas--large", "graph-canvas--mini");
  if (willSwap) {
    pathEl.classList.add("graph-canvas--large");
    graphEl.classList.add("graph-canvas--mini");
  } else {
    graphEl.classList.add("graph-canvas--large");
    pathEl.classList.add("graph-canvas--mini");
  }

  state.graphViewSwapped = willSwap;
  localStorage.setItem("samoyed-graph-swapped", willSwap ? "1" : "0");
  updateGraphViewLabels();
  updateMiniGraphSectionVisibility();
  resizeGraphNetworks({ fitMain: true });
  // Container move breaks cached canvas offsets until redraw.
  requestAnimationFrame(() => {
    state.network?.redraw();
    state.pathNetwork?.redraw();
  });
}

function ensureGeneratedGraphOnMain() {
  if (!state.graphViewSwapped) swapGraphViews();
}

function ensureFullGraphOnMain() {
  if (state.graphViewSwapped) {
    swapGraphViews();
  } else {
    updateGraphViewLabels();
    updateMiniGraphSectionVisibility();
  }
  localStorage.setItem("samoyed-graph-swapped", "0");
}

function restoreGraphViewPreference() {
  if (localStorage.getItem("samoyed-graph-swapped") === "1" && !state.graphViewSwapped) {
    swapGraphViews();
  } else {
    updateGraphViewLabels();
  }
}

function exportFilename(kind) {
  const session = state.sessionId || "session";
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  return `samoyed-${kind}-${session}-${stamp}.png`;
}

function exportNetworkPng(network, filename) {
  const canvas = network?.canvas?.frame?.canvas;
  if (!canvas) {
    alert("No graph to export — load a session or generate paths first.");
    return;
  }

  const exportCanvas = document.createElement("canvas");
  exportCanvas.width = canvas.width;
  exportCanvas.height = canvas.height;
  const ctx = exportCanvas.getContext("2d");
  if (!ctx) return;

  ctx.fillStyle = "#0d1117";
  ctx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);
  ctx.drawImage(canvas, 0, 0);

  const link = document.createElement("a");
  link.download = filename;
  link.href = exportCanvas.toDataURL("image/png");
  link.click();
}

function initPanelResizer() {
  const layout = document.querySelector(".layout");
  const resizer = document.getElementById("panelResizer");
  if (!layout || !resizer) return;

  const stored = localStorage.getItem("samoyed-panel-width");
  if (stored) {
    const width = Math.max(260, Math.min(Number(stored), 720));
    if (Number.isFinite(width)) layout.style.setProperty("--panel-width", `${width}px`);
  }

  let dragging = false;

  const onMove = (event) => {
    if (!dragging) return;
    const rect = layout.getBoundingClientRect();
    const width = Math.max(260, Math.min(rect.right - event.clientX, Math.min(720, window.innerWidth * 0.55)));
    layout.style.setProperty("--panel-width", `${width}px`);
    resizeGraphNetworks();
  };

  const onUp = () => {
    if (!dragging) return;
    dragging = false;
    resizer.classList.remove("dragging");
    document.body.classList.remove("panel-resizing");
    const width = parseInt(getComputedStyle(layout).getPropertyValue("--panel-width"), 10);
    if (Number.isFinite(width)) localStorage.setItem("samoyed-panel-width", String(width));
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup", onUp);
  };

  resizer.addEventListener("mousedown", (event) => {
    event.preventDefault();
    dragging = true;
    resizer.classList.add("dragging");
    document.body.classList.add("panel-resizing");
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function initPathGraph() {
  const container = document.getElementById("pathGraph");
  if (!container) return;

  state.pathNodesDS = new vis.DataSet([]);
  state.pathEdgesDS = new vis.DataSet([]);
  state.pathNetwork = new vis.Network(
    container,
    { nodes: state.pathNodesDS, edges: state.pathEdgesDS },
    {
      physics: { enabled: false },
      interaction: { hover: true, hoverConnectedEdges: true, tooltipDelay: 80 },
      edges: { width: 2, selectionWidth: 2.5, hoverWidth: 3 },
      nodes: { borderWidth: 2, margin: 6 },
    },
  );

  state.pathNetwork.on("doubleClick", (params) => {
    if (params.nodes.length) openNodeDetail(params.nodes[0]);
  });

  state.pathNetwork.on("click", (params) => {
    hideContextMenu();
    if (params.nodes.length) setPathSearchStart(params.nodes[0]);
  });

  wireEdgeInteractionHandlers(state.pathNetwork, state.pathEdgesDS);
}

function fitGraphView(opts = {}) {
  const graphEl = document.getElementById("graph");
  const pathEl = document.getElementById("pathGraph");
  const network = getMainViewportNetwork();
  const container = isGraphOnMain() ? graphEl : pathEl;
  if (!network || !container) return;
  resizeNetworkToContainer(network, container);

  const focusIds = opts.nodeIds;
  if (focusIds?.length) {
    try {
      network.fit({
        nodes: focusIds,
        animation: { duration: 350, easingFunction: "easeInOutQuad" },
        padding: 48,
      });
      return;
    } catch {
      // fall through to full fit
    }
  }

  const hasNodes = (state.nodesDS?.get()?.length || 0) + (state.pathNodesDS?.get()?.length || 0);
  if (!hasNodes) return;
  network.fit({ animation: { duration: 350, easingFunction: "easeInOutQuad" } });
}

function primaryLayoutFocusIds(visibleNodes, edges, rootId) {
  if (!visibleNodes?.length) return null;
  const { undirected } = buildAdjacency(visibleNodes, edges);
  const components = findConnectedComponents(visibleNodes, undirected);
  if (!components.length) return null;
  const nodeById = graphNodeMap(visibleNodes);
  components.sort(
    (a, b) => scoreLayoutComponent(b, nodeById, rootId) - scoreLayoutComponent(a, nodeById, rootId),
  );
  return components[0];
}

function applyGraphLayout(visibleNodes, edges, { fit = false } = {}) {
  state.callerNodeId = findScenarioStartNode(visibleNodes);
  state.layoutRootId = state.callerNodeId || visibleNodes[0]?.id || null;
  state.nodePositions = computeLayeredLayout(visibleNodes, edges, state.layoutRootId);

  state.nodesDS.update(visibleNodes.map((node) => toVisNode(node, state.nodePositions[node.id])));
  if (fit) {
    const focusIds = primaryLayoutFocusIds(visibleNodes, edges, state.layoutRootId);
    fitGraphView({ nodeIds: focusIds });
  }
}

function renderGraph(graph) {
  state.graph = graph;
  const { nodes: visibleNodes, edges } = normalizeGraphForDisplay(graph);
  state.nodesDS.clear();
  state.edgesDS.clear();

  const nodeIds = new Set(visibleNodes.map((n) => n.id));
  const nodeById = graphNodeMap(visibleNodes);
  const layoutEdges = annotateEdgeSourceIndex(edges);

  state.nodesDS.add(visibleNodes.map((node) => toVisNode(node)));
  state.edgesDS.add(buildVisEdges(layoutEdges, nodeById));
  applyGraphLayout(visibleNodes, layoutEdges);

  populateNodeDatalist(visibleNodes);
  refreshGraphViewports({ fit: true });
}

/** Merge server graph into UI without resetting layout (after markings / propagation). */
function syncGraphFromServer(graph) {
  state.graph = graph;
  const { nodes: visibleNodes, edges } = normalizeGraphForDisplay(graph);
  const nodeIds = new Set(visibleNodes.map((n) => n.id));
  const nodeById = graphNodeMap(visibleNodes);
  const layoutEdges = annotateEdgeSourceIndex(edges);

  const existingIds = new Set(state.nodesDS.getIds());
  visibleNodes.forEach((node) => {
    const vis = toVisNode(node, state.nodePositions[node.id]);
    if (existingIds.has(node.id)) {
      state.nodesDS.update(vis);
    } else {
      state.nodesDS.add(vis);
    }
  });
  existingIds.forEach((id) => {
    if (!nodeIds.has(id)) state.nodesDS.remove(id);
  });

  state.edgesDS.clear();
  state.edgesDS.add(buildVisEdges(layoutEdges, nodeById));
  populateNodeDatalist(visibleNodes);
  refreshPathGraphNodeStyles();

  if (state.selectedNodeId && nodeIds.has(state.selectedNodeId)) {
    refreshMainGraphSelection();
  }
}

function refreshPathGraphNodeStyles() {
  if (!state.pathNodesDS || !state.graph?.nodes) return;
  const byId = new Map((state.graph.nodes || []).map((n) => [n.id, n]));
  const updates = [];
  const emptyStart = state.generatedPaths?.[0]?.empty
    ? state.generatedPaths[0]?.node_ids?.[0]
    : null;
  for (const vis of state.pathNodesDS.get()) {
    const raw = byId.get(vis.id);
    if (!raw) continue;
    const next = toVisNode(raw, { x: vis.x, y: vis.y });
    if (vis.id === state.selectedNodeId || vis.id === emptyStart) {
      next.color = SELECTED_NODE_COLOR;
      next.borderWidth = 3;
    } else if (raw.is_high_value || raw.is_compromised) {
      next.borderWidth = 3;
    } else if (state.generatedPaths?.length) {
      next.color = PATH_NODE_COLOR;
      next.borderWidth = 3;
    }
    updates.push(next);
  }
  if (updates.length) state.pathNodesDS.update(updates);
}

function populateNodeDatalist(nodes) {
  const dl = document.getElementById("nodeOptions");
  dl.innerHTML = '<option value="caller">caller (compromised identity)</option>';
  const seen = new Set(["caller"]);
  // One option per node: the graph node id (e.g. Principal:arn:…:role/x).
  // Emitting arn / short name / native_id as separate values duplicates the same
  // identity and breaks resolve when those aliases match multiple nodes.
  nodes
    .slice()
    .sort((a, b) => displayName(a).localeCompare(displayName(b)))
    .forEach((n) => {
      const value = String(n.id || "");
      if (!value || seen.has(value)) return;
      seen.add(value);
      const opt = document.createElement("option");
      opt.value = value;
      opt.label = `${n.label}: ${displayName(n)}`;
      dl.appendChild(opt);
    });
}

function collectPathSubgraph(paths) {
  const hiddenIds = new Set(
    (state.graph.nodes || []).filter(isHiddenDisplayNode).map((n) => n.id),
  );
  const nodeIds = new Set();
  const steps = [];
  const stepKeys = new Set();
  for (const p of paths || []) {
    for (const id of p.node_ids || []) {
      if (!hiddenIds.has(id)) nodeIds.add(id);
    }
    for (const s of p.steps || []) {
      let src = s.src;
      let dst = s.dst;
      let rel = s.rel;
      // Skip edges into hidden nodes (incl. suppressed AttackOutcome endpoints).
      if (hiddenIds.has(src) || (dst && hiddenIds.has(dst))) continue;
      if (rel === "CAN_PRIVESC_TO" && src === dst) continue;
      const key = `${src}|${rel}|${dst}`;
      if (stepKeys.has(key)) continue;
      stepKeys.add(key);
      nodeIds.add(src);
      if (dst) nodeIds.add(dst);
      steps.push({ ...s, src, dst, rel });
    }
  }
  return { nodeIds, steps };
}

function updateMiniGraphSectionVisibility() {
  const section = document.getElementById("pathGraphSection");
  if (!section) return;
  const show = Boolean(state.generatedPaths?.length) || state.graphViewSwapped;
  section.style.display = show ? "block" : "none";
}

function clearGeneratedPathGraph() {
  state.generatedPaths = null;
  if (state.pathNodesDS) state.pathNodesDS.clear();
  if (state.pathEdgesDS) state.pathEdgesDS.clear();
  updateMiniGraphSectionVisibility();
}

function resolvePathGraphStartId(preferred) {
  const candidates = [
    preferred,
    document.getElementById("startSearch")?.value,
    document.getElementById("queryStart")?.value,
    state.selectedNodeId,
    state.callerNodeId,
  ];
  const nodes = state.graph?.nodes || [];
  for (const candidate of candidates) {
    if (!candidate || candidate === "caller") continue;
    if (nodes.some((n) => n.id === candidate)) return candidate;
    const resolved = resolveStartNodeId(candidate);
    if (resolved && resolved !== "caller" && nodes.some((n) => n.id === resolved)) return resolved;
  }
  if (state.callerNodeId && nodes.some((n) => n.id === state.callerNodeId)) return state.callerNodeId;
  return null;
}

function renderGeneratedPathGraph(paths, { fit = true } = {}) {
  if (!state.pathNodesDS || !state.pathEdgesDS || !paths?.length) {
    clearGeneratedPathGraph();
    return;
  }

  const { nodeIds, steps } = collectPathSubgraph(paths);
  const visibleNodes = state.graph.nodes.filter((n) => nodeIds.has(n.id) && !isHiddenDisplayNode(n));
  if (!visibleNodes.length) {
    clearGeneratedPathGraph();
    return;
  }

  const rootId = paths[0]?.node_ids?.[0] || visibleNodes[0].id;
  const nodeById = graphNodeMap(visibleNodes);
  const stepEdges = resolveStepEdges(steps);
  const positions = computeLayeredLayout(visibleNodes, stepEdges, rootId);
  const emptyResult = Boolean(paths[0]?.empty);

  state.pathNodesDS.clear();
  state.pathEdgesDS.clear();
  state.pathNodesDS.add(
    visibleNodes.map((node) => {
      const vis = toVisNode(node, positions[node.id]);
      if (node.id === rootId) {
        vis.color = SELECTED_NODE_COLOR;
        vis.borderWidth = 3;
      } else {
        vis.color = PATH_NODE_COLOR;
        vis.borderWidth = 3;
      }
      return vis;
    }),
  );
  state.pathEdgesDS.add(buildPathViewEdges(stepEdges, nodeById));

  const badge = document.getElementById("pathGraphBadge");
  if (badge) {
    badge.textContent = emptyResult
      ? `1 node · 0 paths`
      : `${visibleNodes.length} nodes · ${paths.length} path${paths.length === 1 ? "" : "s"}`;
  }

  if (fit && state.pathNetwork) {
    requestAnimationFrame(() => {
      const pathEl = document.getElementById("pathGraph");
      if (pathEl) resizeNetworkToContainer(state.pathNetwork, pathEl);
      state.pathNetwork.fit({ animation: { duration: 400, easingFunction: "easeInOutQuad" } });
    });
  }
}

function showGeneratedPaths(paths, { startNodeId } = {}) {
  const list = paths || [];
  if (!list.length) {
    const startId = resolvePathGraphStartId(startNodeId);
    if (startId) {
      state.generatedPaths = [{ node_ids: [startId], steps: [], empty: true }];
      updateMiniGraphSectionVisibility();
      ensureGeneratedGraphOnMain();
      renderGeneratedPathGraph(state.generatedPaths, { fit: true });
      return;
    }
    clearGeneratedPathGraph();
    return;
  }
  state.generatedPaths = list;
  updateMiniGraphSectionVisibility();
  ensureGeneratedGraphOnMain();
  renderGeneratedPathGraph(list, { fit: true });
}

function refreshMainGraphSelection() {
  if (!state.selectedNodeId) return;
  state.nodesDS.get().forEach((n) => {
    const raw = n._raw;
    const ignored = state.ignoredNodeIds.has(n.id);
    if (n.id === state.selectedNodeId) {
      state.nodesDS.update({
        id: n.id,
        color: SELECTED_NODE_COLOR,
        borderWidth: 3,
        opacity: ignored ? 0.55 : 1,
        font: { color: ignored ? "#8b949e" : "#e6edf3", size: 12, multi: true, align: "center" },
      });
    } else {
      const colors = raw ? nodeMarkingColor(raw) : nodeColor(n.group);
      state.nodesDS.update({
        id: n.id,
        color: { ...colors },
        borderWidth: 2,
        opacity: ignored ? 0.35 : 1,
        font: { color: ignored ? "#8b949e" : "#e6edf3", size: 12, multi: true, align: "center" },
      });
    }
  });
}

function setPathSearchStart(nodeId) {
  state.selectedNodeId = nodeId;
  document.getElementById("startSearch").value = nodeId;
  const queryStart = document.getElementById("queryStart");
  if (queryStart) queryStart.value = nodeId;
  refreshMainGraphSelection();
  resizeGraphNetworks();
}

function clearHighlight() {
  state.selectedNodeId = null;
  const { nodes: visibleNodes, edges } = normalizeGraphForDisplay(state.graph);
  state.nodesDS.update(visibleNodes.map((node) => toVisNode(node, state.nodePositions[node.id])));
  const nodeById = graphNodeMap(visibleNodes);
  const layoutEdges = annotateEdgeSourceIndex(edges);
  state.edgesDS.update(buildVisEdges(layoutEdges, nodeById));
  clearGeneratedPathGraph();
}

function openNodeDetail(nodeId) {
  state.selectedNodeId = nodeId;
  const visNode = state.nodesDS.get(nodeId);
  const raw = visNode?._raw || state.graph.nodes.find((n) => n.id === nodeId);
  if (!raw) return;

  document.getElementById("nodeHint").style.display = "none";
  const detail = document.getElementById("nodeDetail");
  detail.style.display = "block";
  detail.dataset.nodeId = nodeId;
  document.getElementById("nodeTitle").textContent = `${raw.label} — ${displayName(raw)}`;
  const { id, label, ...props } = raw;
  document.getElementById("nodeProps").textContent = JSON.stringify(props, null, 2);

  refreshMainGraphSelection();
  switchTab("node");
}

function refreshOpenNodeDetail() {
  const detail = document.getElementById("nodeDetail");
  const nodeId = detail?.dataset?.nodeId || state.selectedNodeId;
  if (!nodeId || detail?.style.display === "none") return;
  const visNode = state.nodesDS?.get(nodeId);
  const raw = visNode?._raw || state.graph.nodes.find((n) => n.id === nodeId);
  if (!raw) return;
  document.getElementById("nodeTitle").textContent = `${raw.label} — ${displayName(raw)}`;
  const { id, label, ...props } = raw;
  document.getElementById("nodeProps").textContent = JSON.stringify(props, null, 2);
}

function selectNode(nodeId) {
  openNodeDetail(nodeId);
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
}

function renderPaths(paths, mode = "paths", opts = {}) {
  const ul = document.getElementById(opts.listId || "paths");
  const countEl = document.getElementById(opts.countId || "pathCount");
  countEl.textContent = String(paths.length);
  ul.innerHTML = "";

  if (!paths.length) {
    const hint =
      mode === "blast"
        ? "No blast-radius paths found — no outgoing edges matched."
        : mode === "neighbors"
          ? "No neighbors found for this node."
          : "No paths found for this query — start node is shown alone.";
    ul.innerHTML = `<li class="empty">${hint}</li>`;
    return;
  }

    paths.forEach((p) => {
    const li = document.createElement("li");
    const target = p.target_match?.blast_label
      || p.target_match?.outcome_display
      || (p.target_match?.concept_type === "AttackOutcome" ? "👑 Administrator access" : null)
      || p.target_match?.concept_type
      || p.target_match?.resource_type
      || "target";
    const steps = (p.steps || []).map((s) => (s.evidence?.attack_outcome ? "👑" : s.rel)).join(" → ");
    li.innerHTML = `
      <div class="title"><span class="score">${p.score ?? "—"}</span> → ${target}</div>
      <div class="path-step">${steps || "direct"}</div>
    `;
    li.onclick = () => {
      const list = document.getElementById(opts.listId || "paths");
      list.querySelectorAll("li").forEach((item) => item.classList.remove("active"));
      li.classList.add("active");
      renderGeneratedPathGraph([p], { fit: true });
    };
    ul.appendChild(li);
  });
}

function resolveStartNodeId(input) {
  const raw = (input || "").trim();
  if (!raw || raw === "caller") {
    if (state.callerNodeId) return state.callerNodeId;
    const nodes = (state.graph.nodes || []).filter((n) => n.label !== "CollectionSession");
    const callerArn = state.sessionMeta?.caller_arn;
    if (callerArn) {
      const arnMatch = nodes.find(
        (n) => n.arn === callerArn || n.native_id === callerArn || n.id === callerArn,
      );
      if (arnMatch) return arnMatch.id;
    }
    const scenarioStart = findScenarioStartNode(nodes);
    if (scenarioStart) return scenarioStart;
    if (nodes.length === 1) return nodes[0].id;
    return "caller";
  }
  const nodes = (state.graph.nodes || []).filter((n) => n.label !== "CollectionSession");
  const exact = nodes.find((n) => n.id === raw);
  if (exact) return exact.id;

  const lower = raw.toLowerCase();
  const matches = nodes.filter((n) => {
    const fields = [n.id, n.arn, n.native_id, n.display_name, n.name].filter(Boolean);
    return fields.some((f) => String(f).toLowerCase() === lower)
      || fields.some((f) => String(f).toLowerCase().includes(lower) || lower.includes(String(f).toLowerCase()));
  });
  if (matches.length === 1) return matches[0].id;
  return raw;
}

async function runPathQuery(query) {
  if (!state.sessionId) return alert("Select a session first");
  const mode = query.mode ?? document.getElementById("searchMode").value;
  const startInput = query.start ?? (document.getElementById("startSearch").value || "caller");
  const maxDepthRaw = query.max_depth ?? document.getElementById("maxDepth").value;
  const maxDepth = Number(maxDepthRaw) > 0 ? Number(maxDepthRaw) : 6;

  try {
    const body = {
      start: resolveStartNodeId(startInput),
      target_concept: query.target_concept ?? (document.getElementById("targetConcept").value || null),
      target_resource_type: query.target_resource_type ?? (document.getElementById("targetResourceType").value || null),
      max_depth: maxDepth,
      mode,
    };
    if (!body.target_concept) delete body.target_concept;
    if (!body.target_resource_type) delete body.target_resource_type;
    const ignored = excludedNodeIdsPayload();
    if (ignored) body.exclude_node_ids = ignored;

    state.lastPathQuery = {
      mode: body.mode,
      start: body.start,
      target_concept: body.target_concept || null,
      target_resource_type: body.target_resource_type || null,
      max_depth: body.max_depth,
    };

    const data = await fetchJSON(`/api/sessions/${state.sessionId}/paths/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (data.start) {
      document.getElementById("startSearch").value = data.start;
      const queryStart = document.getElementById("queryStart");
      if (queryStart) queryStart.value = data.start;
    }

    renderPaths(data.paths || [], mode);
    showGeneratedPaths(data.paths || [], { startNodeId: data.start || body.start });
    return data;
  } catch (err) {
    console.error("Path search failed", err);
    alert(`Path search failed: ${err.message || err}`);
  }
}

async function runSuggestion(suggestion) {
  document.getElementById("searchMode").value = suggestion.mode === "scenario" ? "paths" : suggestion.mode;
  if (suggestion.start) document.getElementById("startSearch").value = suggestion.start;
  if (suggestion.target_concept) document.getElementById("targetConcept").value = suggestion.target_concept;
  if (suggestion.max_depth) document.getElementById("maxDepth").value = suggestion.max_depth;

  if (suggestion.mode === "scenario") {
    const data = await fetchJSON(`/api/scenarios/${suggestion.scenario}/run?session_id=${state.sessionId}`, {
      method: "POST",
    });
    renderPaths(data.paths || [], suggestion.mode === "scenario" ? "paths" : suggestion.mode);
    showGeneratedPaths(data.paths || [], { startNodeId: data.start || suggestion.start });
    switchTab("search");
    return;
  }

  await runPathQuery(suggestion);
  switchTab("search");
}

async function loadSuggestions() {
  const ul = document.getElementById("suggestions");
  const hint = document.getElementById("suggestionsHint");
  if (!state.sessionId) {
    ul.innerHTML = "";
    hint.style.display = "block";
    return;
  }
  hint.style.display = "none";
  const suggestions = await fetchJSON(`/api/sessions/${state.sessionId}/search-suggestions?limit=10`);
  ul.innerHTML = "";
  suggestions.forEach((s, i) => {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="title"><span class="suggestion-rank">${i + 1}</span>${s.title}</div>
      <div class="desc">${s.description}</div>
    `;
    li.onclick = () => runSuggestion(s);
    ul.appendChild(li);
  });
}

async function loadSession(sessionId) {
  if (!sessionId) return;
  try {
    state.sessionId = sessionId;
    loadIgnoredForSession(sessionId);
    const [meta, graph] = await Promise.all([
      fetchJSON(`/api/sessions/${sessionId}`),
      fetchJSON(`/api/sessions/${sessionId}/graph`),
    ]);
    state.sessionMeta = meta;
    document.getElementById("sessionBadge").textContent = `${sessionDisplayName(meta)} · ${shortId(meta.caller_arn)}`;
    ensureFullGraphOnMain();
    state.selectedNodeId = null;
    state.generatedPaths = null;
    if (state.pathNodesDS) state.pathNodesDS.clear();
    if (state.pathEdgesDS) state.pathEdgesDS.clear();
    updateMiniGraphSectionVisibility();
    renderGraph(graph);
    renderIgnoredChips();
    renderPaths([]);
    const defaultStart = state.callerNodeId || "caller";
    document.getElementById("startSearch").value = defaultStart;
    const queryStart = document.getElementById("queryStart");
    if (queryStart) queryStart.value = defaultStart;
    await Promise.all([loadSuggestions(), refreshMarkingsUI()]);

    document.getElementById("searchMode").value = "blast";
    document.querySelectorAll("#sessions li").forEach((li) => {
      li.classList.toggle("active", li.dataset.id === sessionId);
    });

    refreshGraphViewports({ fit: true });
  } catch (err) {
    console.error("Failed to load session", sessionId, err);
    alert(`Could not load session: ${err.message || err}`);
  }
}

async function runGraphQuery() {
  if (!state.sessionId) return alert("Select a session first");
  const relRaw = document.getElementById("queryRelTypes").value.trim();
  const relTypes = relRaw ? relRaw.split(",").map((s) => s.trim()).filter(Boolean) : null;
  const maxDepth = Number(document.getElementById("queryMaxDepth").value) || 6;
  const maxPaths = Number(document.getElementById("queryMaxPaths").value) || 20;

  try {
    const body = {
      start: resolveStartNodeId(document.getElementById("queryStart").value || "caller"),
      mode: document.getElementById("queryMode").value,
      target_concept: document.getElementById("queryTargetConcept").value || null,
      target_resource_type: document.getElementById("queryTargetResourceType").value.trim() || null,
      end_node_id: document.getElementById("queryEndNodeId").value.trim() || null,
      end_id_contains: document.getElementById("queryEndContains").value.trim() || null,
      rel_types: relTypes,
      max_depth: maxDepth,
      max_paths: maxPaths,
    };
    if (!body.target_concept) delete body.target_concept;
    if (!body.target_resource_type) delete body.target_resource_type;
    if (!body.end_node_id) delete body.end_node_id;
    if (!body.end_id_contains) delete body.end_id_contains;
    if (!body.rel_types?.length) delete body.rel_types;
    const ignored = excludedNodeIdsPayload();
    if (ignored) body.exclude_node_ids = ignored;

    const data = await fetchJSON(`/api/sessions/${state.sessionId}/graph/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (data.start) document.getElementById("queryStart").value = data.start;
    const paths = data.paths || [];
    renderPaths(paths, body.mode, { listId: "queryPaths", countId: "queryPathCount" });
    showGeneratedPaths(paths, { startNodeId: data.start || body.start });
    switchTab("query");
    return data;
  } catch (err) {
    console.error("Graph query failed", err);
    alert(`Graph query failed: ${err.message || err}`);
  }
}

function sessionDisplayName(summary) {
  const short = summary.short_name || summary.metadata?.short_name;
  if (short && short !== summary.session_id) {
    return `${short} · ${summary.session_id}`;
  }
  return summary.session_id;
}

function sessionSourceLabel(metadata) {
  const source = metadata?.source || metadata?.scenario || "";
  const nodes = metadata?.node_count;
  const parts = [];
  if (source) parts.push(source);
  if (nodes != null) parts.push(`${nodes} nodes`);
  return parts.join(" · ") || "session";
}

async function loadConnectors() {
  const select = document.getElementById("importConnector");
  if (!select) return;
  const connectors = await fetchJSON("/api/connectors");
  select.innerHTML = "";
  connectors
    .filter((c) => c.file_import)
    .forEach((c) => {
      const opt = document.createElement("option");
      opt.value = c.id;
      opt.textContent = c.label;
      opt.title = c.description || "";
      select.appendChild(opt);
    });
}

async function importReport() {
  const connector = document.getElementById("importConnector").value;
  const fileInput = document.getElementById("importFile");
  const status = document.getElementById("importStatus");
  if (!connector) return alert("Select a connector");
  if (!fileInput.files?.length) return alert("Choose a report file");

  status.textContent = "Importing…";
  const form = new FormData();
  form.append("connector", connector);
  form.append("file", fileInput.files[0]);
  const callerArn = document.getElementById("importCallerArn").value.trim();
  if (callerArn) form.append("caller_arn", callerArn);

  try {
    const res = await fetch("/api/sessions/import", {
      method: "POST",
      credentials: "same-origin",
      body: form,
    });
    if (res.status === 401) {
      window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
      return;
    }
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || res.statusText);
    }
    const data = await res.json();
    status.textContent = `Imported ${data.session_id} (${data.metadata?.node_count ?? "?"} nodes)`;
    fileInput.value = "";
    await refreshSessions({ scope: "ids", ids: [data.session_id], autoLoad: true, loadId: data.session_id });
  } catch (err) {
    status.textContent = "";
    alert(`Import failed: ${err.message || err}`);
  }
}

function sessionsQueryParams(opts = {}) {
  const scope = opts.scope ?? state.sessionListScope;
  const params = new URLSearchParams();
  params.set("scope", scope);
  if (scope === "recent") {
    params.set("limit", String(opts.limit ?? 1));
  } else if (scope === "all") {
    params.set("limit", String(opts.limit ?? 500));
  } else if (scope === "ids") {
    const ids = opts.ids ?? state.sessionSelectionIds;
    if (ids?.length) params.set("ids", ids.join(","));
  }
  if (opts.includeDemos) params.set("include_demos", "true");
  return params.toString();
}

async function refreshSessions(opts = {}) {
  const scope = opts.scope ?? state.sessionListScope;
  if (scope === "ids" && opts.ids) {
    state.sessionListScope = "ids";
    state.sessionSelectionIds = opts.ids;
    const select = document.getElementById("sessionScope");
    if (select) select.value = "recent";
  } else if (scope === "recent" || scope === "all") {
    state.sessionListScope = scope;
    state.sessionSelectionIds = null;
    const select = document.getElementById("sessionScope");
    if (select) select.value = scope;
  }

  const sessions = await fetchJSON(`/api/sessions?${sessionsQueryParams(opts)}`);
  const ul = document.getElementById("sessions");
  const hint = document.getElementById("sessionsHint");
  ul.innerHTML = "";

  if (!sessions.length) {
    if (hint) {
      hint.textContent =
        scope === "ids"
          ? "No matching session"
          : "No sessions yet — import a report above, or load a demo fixture";
      hint.style.display = "block";
    }
    return;
  }

  sessions.forEach((s) => {
    const li = document.createElement("li");
    li.dataset.id = s.session_id;
    li.setAttribute("role", "button");
    li.tabIndex = 0;
    const meta = s.metadata || {};
    const demoTag = s.is_demo ? " · demo" : "";
    li.innerHTML = `
      <div class="title">${sessionDisplayName(s)}${state.sessionId === s.session_id ? " ✓" : ""}</div>
      <div class="desc">${shortId(s.caller_arn || "")} · ${sessionSourceLabel(meta)}${demoTag}</div>
    `;
    if (state.sessionId === s.session_id) li.classList.add("active");
    ul.appendChild(li);
  });

  if (hint) {
    if (scope === "recent" && sessions.length === 1) {
      hint.textContent = "Showing most recent session — switch to All for full list";
    } else if (scope === "ids") {
      hint.textContent = "Showing selected session(s)";
    } else {
      hint.textContent = `${sessions.length} session(s) — click to load`;
    }
    hint.style.display = "block";
  }

  if (opts.autoLoad && sessions.length) {
    const target = opts.loadId ?? sessions[0].session_id;
    if (target !== state.sessionId) await loadSession(target);
  } else if (state.sessionId) {
    document.querySelectorAll("#sessions li").forEach((li) => {
      li.classList.toggle("active", li.dataset.id === state.sessionId);
    });
  }
}

async function loadFixturesCatalog() {
  const select = document.getElementById("fixtureSelect");
  if (!select) return;
  const fixtures = await fetchJSON("/api/fixtures");
  select.innerHTML = "";
  fixtures.forEach((f) => {
    const opt = document.createElement("option");
    opt.value = f.id;
    opt.textContent = `${f.id} — ${f.description}`;
    select.appendChild(opt);
  });
}

async function loadFixtureSession() {
  const fixtureId = document.getElementById("fixtureSelect")?.value;
  if (!fixtureId) return;
  const s = await fetchJSON(`/api/sessions/fixtures/${fixtureId}`, { method: "POST" });
  await refreshSessions({ scope: "ids", ids: [s.session_id], autoLoad: true, loadId: s.session_id });
  return s;
}

async function markSelectedNode({ compromised, high_value, clear = false }) {
  if (!state.sessionId) return alert("Select a session first");
  const nodeId =
    state.selectedNodeId
    || resolvePathGraphStartId(document.getElementById("startSearch")?.value)
    || resolvePathGraphStartId(document.getElementById("queryStart")?.value);
  if (!nodeId) return alert("Select a node first (click it, or put it in Start)");
  return markNode(nodeId, { compromised, high_value, clear });
}

async function markNode(nodeId, { compromised, high_value, clear = false, refreshPaths = true }) {
  if (!state.sessionId || !nodeId) return;
  const status = document.getElementById("markStatus");
  if (status) status.textContent = "Updating…";
  try {
    const body = {
      refs: [nodeId],
      source: "ui",
      clear,
    };
    if (compromised !== undefined) body.compromised = compromised;
    if (high_value !== undefined) body.high_value = high_value;
    const result = await fetchJSON(`/api/sessions/${state.sessionId}/markings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const [graph] = await Promise.all([
      fetchJSON(`/api/sessions/${state.sessionId}/graph`),
      refreshMarkingsUI(),
    ]);
    syncGraphFromServer(graph);
    if (state.selectedNodeId === nodeId) {
      refreshMainGraphSelection();
      const raw = state.graph.nodes.find((n) => n.id === nodeId);
      if (raw && document.getElementById("nodeDetail").style.display !== "none") {
        const { id, label, ...props } = raw;
        document.getElementById("nodeProps").textContent = JSON.stringify(props, null, 2);
      }
    }
    const marked = result.marked?.[0];
    if (status) {
      status.textContent = marked
        ? `Marked — compromised: ${!!marked.is_compromised}, high-value: ${!!marked.is_high_value}`
        : "No changes";
    }
    if (result.propagated?.length) {
      if (status) status.textContent += ` · ${result.propagated.length} propagated`;
    }
    if (refreshPaths && state.markings?.compromised_count && state.markings?.high_value_count) {
      await runMarkingPathsQuery("compromised_to_high_value", { silent: true });
    }
    return result;
  } catch (err) {
    if (status) status.textContent = "";
    alert(`Mark failed: ${err.message || err}`);
  }
}

async function refreshMarkingsUI() {
  const el = document.getElementById("markingsSummary");
  if (!state.sessionId || !el) return null;
  try {
    const summary = await fetchJSON(`/api/sessions/${state.sessionId}/markings`);
    state.markings = summary;
    const parts = [];
    if (summary.compromised_count) {
      parts.push(`<span class="marking-chip compromised">${summary.compromised_count} compromised</span>`);
    }
    if (summary.high_value_count) {
      parts.push(`<span class="marking-chip high-value">${summary.high_value_count} high-value</span>`);
    }
    if (summary.shadow_admin_count) {
      parts.push(`<span class="marking-chip shadow-admin">${summary.shadow_admin_count} shadow admin</span>`);
    }
    if (parts.length) {
      el.innerHTML = parts.join("") + '<div style="margin-top:6px;font-size:11px;color:var(--muted)">Right-click nodes to add or change markings</div>';
    } else {
      el.textContent = "Right-click nodes to mark compromised or high-value";
    }
    return summary;
  } catch (err) {
    console.warn("Could not refresh markings", err);
    return null;
  }
}

async function runMarkingPathsQuery(kind, { silent = false } = {}) {
  if (!state.sessionId) return alert("Select a session first");
  const maxDepth = Number(document.getElementById("maxDepth")?.value) || 6;
  try {
    const body = { kind, max_depth: maxDepth, max_paths: 30 };
    const ignored = excludedNodeIdsPayload();
    if (ignored) body.exclude_node_ids = ignored;
    const data = await fetchJSON(`/api/sessions/${state.sessionId}/paths/markings-query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    state.markings = data.markings || state.markings;
    refreshMarkingsSummaryFromData(data.markings);
    renderPaths(data.paths || [], kind === "blast_compromised" ? "blast" : "paths");
    showGeneratedPaths(data.paths || [], {
      startNodeId: data.start || state.selectedNodeId || state.callerNodeId,
    });
    switchTab("search");
    return data;
  } catch (err) {
    if (!silent) alert(`Marking query failed: ${err.message || err}`);
    console.error("Marking query failed", err);
  }
}

function refreshMarkingsSummaryFromData(summary) {
  const el = document.getElementById("markingsSummary");
  if (!el || !summary) return;
  const parts = [];
  if (summary.compromised_count) {
    parts.push(`<span class="marking-chip compromised">${summary.compromised_count} compromised</span>`);
  }
  if (summary.high_value_count) {
    parts.push(`<span class="marking-chip high-value">${summary.high_value_count} high-value</span>`);
  }
  if (summary.shadow_admin_count) {
    parts.push(`<span class="marking-chip shadow-admin">${summary.shadow_admin_count} shadow admin</span>`);
  }
  if (parts.length) {
    el.innerHTML = parts.join("") + '<div style="margin-top:6px;font-size:11px;color:var(--muted)">Right-click nodes to add or change markings</div>';
  }
}

let contextMenuEl = null;

function nodeIdAtPointer(network, event) {
  if (!network) return null;
  const canvas = network.canvas?.frame?.canvas;
  if (!canvas) return null;
  const rect = canvas.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return null;
  const pointer = {
    x: event.clientX - rect.left,
    y: event.clientY - rect.top,
  };
  if (pointer.x < 0 || pointer.y < 0 || pointer.x > rect.width || pointer.y > rect.height) {
    return null;
  }
  try {
    return network.getNodeAt(pointer) || null;
  } catch {
    return null;
  }
}

function handleGraphHostContextMenu(event, network) {
  if (!network) return;
  const nodeId = nodeIdAtPointer(network, event);
  event.preventDefault();
  event.stopPropagation();
  hideContextMenu();
  if (nodeId) setPathSearchStart(nodeId);
  showContextMenu(event, nodeId || null);
}

function initGraphContextMenus() {
  const mainHost = document.getElementById("mainGraphHost");
  const miniHost = document.getElementById("miniGraphHost");
  mainHost?.addEventListener("contextmenu", (event) => {
    handleGraphHostContextMenu(event, getMainViewportNetwork());
  });
  miniHost?.addEventListener("contextmenu", (event) => {
    handleGraphHostContextMenu(event, getMiniViewportNetwork());
  });
}

function initContextMenu() {
  contextMenuEl = document.createElement("div");
  contextMenuEl.id = "graphContextMenu";
  contextMenuEl.className = "context-menu";
  document.body.appendChild(contextMenuEl);
  // Left-click outside dismisses; right-click must not immediately close the menu we just opened.
  document.addEventListener("mousedown", (event) => {
    if (!contextMenuEl || contextMenuEl.style.display === "none") return;
    if (event.button !== 0) return;
    if (contextMenuEl.contains(event.target)) return;
    hideContextMenu();
  });
  document.addEventListener("scroll", hideContextMenu, true);
  initGraphContextMenus();
  ensureEnrichBusyIndicator();
}

function hideContextMenu() {
  if (contextMenuEl) contextMenuEl.style.display = "none";
  state.contextMenuNodeId = null;
}

function showContextMenu(event, nodeId) {
  if (!contextMenuEl) return;
  state.contextMenuNodeId = nodeId;
  const raw = nodeId ? state.graph.nodes.find((n) => n.id === nodeId) : null;
  const name = raw ? displayName(raw) : "Session";
  const isIgnored = nodeId ? state.ignoredNodeIds.has(nodeId) : false;

  if (!nodeId) {
    contextMenuEl.innerHTML = `
      <div class="context-menu-header">Graph</div>
      <button type="button" data-action="enrich-session">Enrich session (attack surface)</button>
      <hr />
      <div class="context-menu-section-label">Apply library file</div>
      <div data-role="enrich-library"><div class="context-menu-empty">Loading…</div></div>
    `;
    contextMenuEl.querySelector('[data-action="enrich-session"]').onclick = () => {
      hideContextMenu();
      enrichSessionSurface();
    };
  } else {
    contextMenuEl.innerHTML = `
      <div class="context-menu-header">${escapeHtml(shortId(name))}</div>
      <button type="button" data-action="mark-compromised">Mark compromised</button>
      <button type="button" data-action="mark-high-value" class="warn">Mark high-value</button>
      <button type="button" data-action="clear-markings">Clear markings</button>
      <hr />
      <button type="button" data-action="toggle-ignore">${isIgnored ? "Un-ignore from queries" : "Ignore from queries"}</button>
      <hr />
      <button type="button" data-action="blast-from-here">Blast radius from here</button>
      <button type="button" data-action="paths-from-here">Paths from here → secrets</button>
      <hr />
      <button type="button" data-action="enrich-session">Enrich session (attack surface)</button>
      <div class="context-menu-section-label">Enrich this node</div>
      <div data-role="enrich-library"><div class="context-menu-empty">Loading…</div></div>
      <hr />
      <button type="button" data-action="query-compromised-hv">Query: all compromised → high value</button>
    `;

    contextMenuEl.querySelector('[data-action="mark-compromised"]').onclick = () => {
      hideContextMenu();
      setPathSearchStart(nodeId);
      markNode(nodeId, { compromised: true });
    };
    contextMenuEl.querySelector('[data-action="mark-high-value"]').onclick = () => {
      hideContextMenu();
      setPathSearchStart(nodeId);
      markNode(nodeId, { high_value: true });
    };
    contextMenuEl.querySelector('[data-action="clear-markings"]').onclick = () => {
      hideContextMenu();
      setPathSearchStart(nodeId);
      markNode(nodeId, { compromised: false, high_value: false, clear: true });
    };
    contextMenuEl.querySelector('[data-action="toggle-ignore"]').onclick = () => {
      hideContextMenu();
      setNodeIgnored(nodeId, !isIgnored);
    };
    contextMenuEl.querySelector('[data-action="blast-from-here"]').onclick = () => {
      hideContextMenu();
      document.getElementById("startSearch").value = nodeId;
      runPathQuery({ start: nodeId, mode: "blast" });
      switchTab("search");
    };
    contextMenuEl.querySelector('[data-action="paths-from-here"]').onclick = () => {
      hideContextMenu();
      document.getElementById("startSearch").value = nodeId;
      document.getElementById("searchMode").value = "paths";
      document.getElementById("targetConcept").value = "SecretStore";
      runPathQuery({ start: nodeId, mode: "paths", target_concept: "SecretStore" });
      switchTab("search");
    };
    contextMenuEl.querySelector('[data-action="enrich-session"]').onclick = () => {
      hideContextMenu();
      enrichSessionSurface();
    };
    contextMenuEl.querySelector('[data-action="query-compromised-hv"]').onclick = () => {
      hideContextMenu();
      runMarkingPathsQuery("compromised_to_high_value");
    };
  }

  contextMenuEl.style.display = "block";
  contextMenuEl.style.left = `${event.clientX}px`;
  contextMenuEl.style.top = `${event.clientY}px`;
  const rect = contextMenuEl.getBoundingClientRect();
  if (rect.right > window.innerWidth - 8) {
    contextMenuEl.style.left = `${event.clientX - rect.width}px`;
  }
  if (rect.bottom > window.innerHeight - 8) {
    contextMenuEl.style.top = `${event.clientY - rect.height}px`;
  }

  populateContextEnrichMenu(nodeId);
}

async function populateContextEnrichMenu(nodeId) {
  const slot = contextMenuEl?.querySelector('[data-role="enrich-library"]');
  if (!slot) return;
  const requestNodeId = nodeId;
  try {
    const data = await fetchJSON("/api/enrichment/library");
    if (state.contextMenuNodeId !== requestNodeId) return;
    const files = (data.files || []).filter((f) => f.valid !== false);
    if (!files.length) {
      slot.innerHTML = `<div class="context-menu-empty">No files in library<br/><span style="font-size:10px">${escapeHtml(data.directory || "")}</span></div>`;
      return;
    }
    slot.innerHTML = files
      .slice(0, 12)
      .map((f) => {
        const meta = [f.collector_mode || f.collector, f.material_count != null ? `${f.material_count} mats` : null]
          .filter(Boolean)
          .join(" · ");
        return `<button type="button" class="enrich-file" data-enrich-file="${escapeAttr(f.filename)}">${escapeHtml(f.filename)}${
          meta ? `<span class="enrich-file-meta">${escapeHtml(meta)}</span>` : ""
        }</button>`;
      })
      .join("");
    slot.querySelectorAll("[data-enrich-file]").forEach((btn) => {
      btn.onclick = () => {
        const filename = btn.getAttribute("data-enrich-file");
        const bindTo = state.contextMenuNodeId || requestNodeId || null;
        hideContextMenu();
        applyEnrichmentLibraryFile(filename, bindTo);
      };
    });
  } catch (err) {
    if (state.contextMenuNodeId !== requestNodeId) return;
    slot.innerHTML = `<div class="context-menu-empty">${escapeHtml(String(err.message || err))}</div>`;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/'/g, "&#39;");
}

function ensureEnrichBusyIndicator() {
  if (document.getElementById("enrichBusyBanner")) return;
  const el = document.createElement("div");
  el.id = "enrichBusyBanner";
  el.className = "enrich-busy-banner";
  el.hidden = true;
  el.innerHTML = `<span class="enrich-busy-dot"></span><span data-role="enrich-busy-text">Enriching…</span>`;
  document.body.appendChild(el);
}

function setEnrichBusy(active, message) {
  state.enrichBusy = Boolean(active);
  ensureEnrichBusyIndicator();
  const el = document.getElementById("enrichBusyBanner");
  const text = el?.querySelector('[data-role="enrich-busy-text"]');
  if (!el) return;
  if (active) {
    if (text) text.textContent = message || "Enriching session…";
    el.hidden = false;
  } else {
    el.hidden = true;
  }
  const status = document.getElementById("enrichmentStatus");
  if (status && active) status.textContent = message || "Enriching…";
}

function formatSurfaceEnrichStats(stats) {
  const parts = [];
  if (stats.capability_bindings) parts.push(`${stats.capability_bindings} capability bind(s)`);
  if (stats.feeds_edges) parts.push(`${stats.feeds_edges} FEEDS`);
  if (stats.passrole_ec2_bindings) parts.push(`${stats.passrole_ec2_bindings} PassRole→EC2`);
  if (stats.credential_unlocks) parts.push(`${stats.credential_unlocks} unlock(s)`);
  if (stats.materials_relabeled) parts.push(`${stats.materials_relabeled} relabel(s)`);
  if (stats.imds_surfaces) parts.push(`${stats.imds_surfaces} IMDS`);
  return parts.length ? parts.join(", ") : "surface enrichment complete";
}

function formatEnrichmentStats(stats, label) {
  const unresolved = stats.unresolved_bindings?.length || 0;
  const pending = stats.pending_unlocks?.length || 0;
  const skipped = stats.skipped_materials?.length || 0;
  const hostless = stats.hostless_bindings || 0;
  const parts = [
    `${stats.materials_applied || 0} material(s)`,
    `${stats.edges_added || 0} edge(s)`,
  ];
  if (stats.unlocks_applied) parts.push(`${stats.unlocks_applied} unlock(s)`);
  if (stats.materials_removed) parts.push(`${stats.materials_removed} replaced`);
  if (hostless) parts.push(`${hostless} hostless`);
  if (pending) parts.push(`${pending} pending unlock(s)`);
  if (unresolved) parts.push(`${unresolved} unmatched host ref(s)`);
  if (skipped) parts.push(`${skipped} skipped`);
  if (stats.surface) {
    const surfaceBits = formatSurfaceEnrichStats(stats.surface);
    if (surfaceBits) parts.push(surfaceBits);
  }
  const prefix = label ? `${label}: ` : "";
  if (!(stats.materials_applied || 0) && unresolved) {
    return `${prefix}import matched no nodes — enum a session first`;
  }
  return `${prefix}${parts.join(", ")}`;
}

/** Reload graph + re-run the active query without stealing focus/selection. */
async function afterEnrichmentRefresh(statusMessage) {
  const keepSelected = state.selectedNodeId;
  const keepStart =
    document.getElementById("startSearch")?.value ||
    state.lastPathQuery?.start ||
    "";
  const graph = await fetchJSON(`/api/sessions/${state.sessionId}/graph`);
  syncGraphFromServer(graph);
  refreshGraphViewports({ fit: false });
  if (keepSelected && (state.graph.nodes || []).some((n) => n.id === keepSelected)) {
    state.selectedNodeId = keepSelected;
    refreshMainGraphSelection();
    refreshOpenNodeDetail();
  }
  const startEl = document.getElementById("startSearch");
  if (startEl && keepStart) startEl.value = keepStart;

  if (state.lastPathQuery && state.generatedPaths?.length) {
    const q = { ...state.lastPathQuery };
    await runPathQuery(q);
  }
  const status = document.getElementById("enrichmentStatus");
  if (status && statusMessage) status.textContent = statusMessage;
}

async function enrichSessionSurface() {
  const status = document.getElementById("enrichmentStatus");
  if (!state.sessionId) {
    if (status) status.textContent = "Load a session first";
    return;
  }
  if (state.enrichBusy) return;
  setEnrichBusy(true, "Enriching session…");
  try {
    const data = await fetchJSON(`/api/sessions/${state.sessionId}/enrich-surface`, {
      method: "POST",
    });
    const msg = `Session: ${formatSurfaceEnrichStats(data.stats || {})}`;
    await afterEnrichmentRefresh(msg);
  } catch (err) {
    if (status) status.textContent = String(err.message || err);
  } finally {
    setEnrichBusy(false);
  }
}

async function applyEnrichmentLibraryFile(filename, targetNodeId) {
  const status = document.getElementById("enrichmentStatus");
  if (!state.sessionId) {
    if (status) status.textContent = "Load a session first";
    return;
  }
  if (state.enrichBusy) return;
  setEnrichBusy(true, `Importing ${filename}…`);
  try {
    const qs = targetNodeId
      ? `?target_node_id=${encodeURIComponent(targetNodeId)}`
      : "";
    const data = await fetchJSON(
      `/api/sessions/${state.sessionId}/enrichment/library/${encodeURIComponent(filename)}${qs}`,
      { method: "POST" },
    );
    await afterEnrichmentRefresh(formatEnrichmentStats(data.stats || {}, filename));
    refreshEnrichmentLibrary();
  } catch (err) {
    if (status) status.textContent = String(err.message || err);
  } finally {
    setEnrichBusy(false);
  }
}

async function refreshEnrichmentLibrary() {
  const list = document.getElementById("enrichmentLibraryList");
  const pathEl = document.getElementById("enrichmentLibraryPath");
  if (!list) return;
  try {
    const data = await fetchJSON("/api/enrichment/library");
    if (pathEl) pathEl.textContent = data.directory || "";
    const files = data.files || [];
    if (!files.length) {
      list.innerHTML = `<button type="button" disabled>No enrichment files yet — run <code>samoyed collect</code></button>`;
      return;
    }
    list.innerHTML = files
      .map((f) => {
        const meta = [
          f.valid === false ? "invalid" : null,
          f.collector_mode || f.collector,
          f.material_count != null ? `${f.material_count} materials` : null,
        ]
          .filter(Boolean)
          .join(" · ");
        return `<button type="button" data-library-file="${escapeAttr(f.filename)}" ${
          f.valid === false ? "disabled" : ""
        }>${escapeHtml(f.filename)}${meta ? `<span class="meta">${escapeHtml(meta)}</span>` : ""}</button>`;
      })
      .join("");
    list.querySelectorAll("[data-library-file]").forEach((btn) => {
      btn.onclick = () => {
        const filename = btn.getAttribute("data-library-file");
        applyEnrichmentLibraryFile(filename, state.selectedNodeId || null);
      };
    });
  } catch (err) {
    list.innerHTML = `<button type="button" disabled>${escapeHtml(String(err.message || err))}</button>`;
  }
}

async function appendProperty() {
  if (!state.sessionId || !state.selectedNodeId) return;
  const key = document.getElementById("propKey").value.trim();
  const rawValue = document.getElementById("propValue").value.trim();
  if (!key) return alert("Property key required");

  let value = rawValue;
  try {
    value = JSON.parse(rawValue);
  } catch {
    /* keep string */
  }

  const updated = await fetchJSON(`/api/sessions/${state.sessionId}/nodes`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ node_id: state.selectedNodeId, properties: { [key]: value } }),
  });

  const graph = await fetchJSON(`/api/sessions/${state.sessionId}/graph`);
  syncGraphFromServer(graph);
  selectNode(state.selectedNodeId);
  document.getElementById("propKey").value = "";
  document.getElementById("propValue").value = "";
}

function updateTargetFieldsVisibility() {
  const mode = document.getElementById("searchMode").value;
  document.getElementById("targetFields").style.display = mode === "paths" ? "block" : "none";
}

// Small pure display contract used by regression tests. Keeping this callable
// outside the browser prevents CAN_PRIVESC_TO self-loops from coming back.
globalThis.SamoyedGraphDisplay = {
  normalize(graph, options = {}) {
    if (options.showNetworkEdges != null) {
      state.showNetworkEdges = Boolean(options.showNetworkEdges);
    }
    if (options.showAllResourceAccess != null) {
      state.showAllResourceAccess = Boolean(options.showAllResourceAccess);
    }
    return normalizeGraphForDisplay(graph);
  },
  buildEdges(edges, nodes) {
    return buildVisEdges(edges, graphNodeMap(nodes));
  },
};

if (typeof document !== "undefined" && typeof vis !== "undefined") {
// Event wiring
document.getElementById("refreshSessions").onclick = () => {
  if (state.sessionListScope === "all") {
    refreshSessions({ scope: "all", autoLoad: false });
  } else if (state.sessionSelectionIds?.length) {
    refreshSessions({ scope: "ids", ids: state.sessionSelectionIds, autoLoad: false });
  } else {
    refreshSessions({ scope: "recent", limit: 1, autoLoad: false });
  }
};
document.getElementById("sessionScope").onchange = (event) => {
  const scope = event.target.value;
  if (scope === "all") {
    refreshSessions({ scope: "all", autoLoad: false });
  } else {
    refreshSessions({ scope: "recent", limit: 1, autoLoad: true });
  }
};
document.getElementById("loadFixture").onclick = () => loadFixtureSession();
document.getElementById("runSearch").onclick = () => runPathQuery({});
document.getElementById("startSearch").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    runPathQuery({});
  }
});
document.getElementById("runGraphQuery").onclick = runGraphQuery;
async function applyEnrichmentExample(exampleId) {
  const status = document.getElementById("enrichmentStatus");
  if (!state.sessionId) {
    if (status) status.textContent = "Load a session first";
    return;
  }
  const id = exampleId || document.getElementById("enrichmentExampleSelect")?.value;
  if (!id) {
    if (status) status.textContent = "Choose a lab enrichment example";
    return;
  }
  if (state.enrichBusy) return;
  const bindTo = state.selectedNodeId || state.contextMenuNodeId || null;
  setEnrichBusy(true, "Importing lab example…");
  try {
    const qs = bindTo ? `?target_node_id=${encodeURIComponent(bindTo)}` : "";
    const data = await fetchJSON(
      `/api/sessions/${state.sessionId}/enrichment/examples/${id}${qs}`,
      { method: "POST" },
    );
    await afterEnrichmentRefresh(
      formatEnrichmentStats(data.stats || {}, data.example_id || "lab example"),
    );
  } catch (err) {
    if (status) status.textContent = String(err.message || err);
  } finally {
    setEnrichBusy(false);
  }
}

async function loadEnrichmentExamples() {
  const select = document.getElementById("enrichmentExampleSelect");
  if (!select) return;
  const examples = await fetchJSON("/api/enrichment/examples");
  select.innerHTML = "";
  examples.forEach((ex) => {
    const opt = document.createElement("option");
    opt.value = ex.id;
    opt.textContent = ex.description;
    if (ex.id === "host-pivot-lab") opt.selected = true;
    select.appendChild(opt);
  });
}

async function applyEnrichmentFile(file) {
  const status = document.getElementById("enrichmentStatus");
  if (!state.sessionId) {
    if (status) status.textContent = "Load a session first";
    return;
  }
  if (!file) {
    if (status) status.textContent = "Choose an enrichment JSON file";
    return;
  }
  if (state.enrichBusy) return;
  setEnrichBusy(true, "Importing enrichment…");
  const form = new FormData();
  form.append("file", file);
  if (state.selectedNodeId) {
    form.append("target_node_id", state.selectedNodeId);
  }
  try {
    const res = await fetch(`/api/sessions/${state.sessionId}/enrichment`, {
      method: "POST",
      credentials: "same-origin",
      body: form,
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    await afterEnrichmentRefresh(formatEnrichmentStats(data.stats || {}, file.name));
    refreshEnrichmentLibrary();
  } catch (err) {
    if (status) status.textContent = String(err.message || err);
  } finally {
    setEnrichBusy(false);
  }
}

function initEnrichmentUpload() {
  const applyBtn = document.getElementById("applyEnrichment");
  const applyExampleBtn = document.getElementById("applyEnrichmentExample");
  const refreshLibBtn = document.getElementById("refreshEnrichmentLibrary");
  const fileInput = document.getElementById("enrichmentFile");
  const dropZone = document.getElementById("enrichmentDropZone");

  applyExampleBtn?.addEventListener("click", () => applyEnrichmentExample());
  refreshLibBtn?.addEventListener("click", () => refreshEnrichmentLibrary());
  document.getElementById("enrichSessionSurface")?.addEventListener("click", () => enrichSessionSurface());

  applyBtn?.addEventListener("click", () => {
    applyEnrichmentFile(fileInput?.files?.[0]);
  });

  fileInput?.addEventListener("change", () => {
    if (fileInput.files?.[0]) applyEnrichmentFile(fileInput.files[0]);
  });

  const handleDrop = (event) => {
    event.preventDefault();
    dropZone?.classList.remove("drag-over");
    const file = event.dataTransfer?.files?.[0];
    if (file && file.name.endsWith(".json")) applyEnrichmentFile(file);
  };

  dropZone?.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropZone.classList.add("drag-over");
  });
  dropZone?.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
  dropZone?.addEventListener("drop", handleDrop);
}

document.getElementById("importReport").onclick = importReport;
document.getElementById("fitGraph").onclick = fitGraphView;
document.getElementById("toggleNetworkEdges")?.addEventListener("change", (event) => {
  state.showNetworkEdges = !!event.target.checked;
  if (state.graph) renderGraph(state.graph);
});
document.getElementById("toggleAllResourceAccess")?.addEventListener("change", (event) => {
  state.showAllResourceAccess = !!event.target.checked;
  if (state.graph) renderGraph(state.graph);
});
document.getElementById("exportMainGraph").onclick = () => {
  const onMain = isGraphOnMain();
  exportNetworkPng(
    getMainViewportNetwork(),
    exportFilename(onMain ? "full-graph" : "generated-paths"),
  );
};
document.getElementById("exportPathGraph").onclick = () => {
  const onMain = isGraphOnMain();
  exportNetworkPng(
    getMiniViewportNetwork(),
    exportFilename(onMain ? "generated-paths" : "full-graph"),
  );
};
document.getElementById("swapGraphViews").onclick = swapGraphViews;
document.getElementById("relayoutGraph").onclick = () => {
  const { nodes: visibleNodes, edges } = normalizeGraphForDisplay(state.graph);
  const layoutEdges = annotateEdgeSourceIndex(edges);
  applyGraphLayout(visibleNodes, layoutEdges, { fit: true });
};
document.getElementById("clearHighlight").onclick = clearHighlight;
document.getElementById("focusCaller").onclick = () => {
  if (state.callerNodeId) state.network.focus(state.callerNodeId, { scale: 1.2, animation: true });
};
document.getElementById("appendProp").onclick = appendProperty;
document.getElementById("markCompromised").onclick = () => markSelectedNode({ compromised: true });
document.getElementById("markHighValue").onclick = () => markSelectedNode({ high_value: true });
document.getElementById("clearMarkings").onclick = () =>
  markSelectedNode({ compromised: false, high_value: false, clear: true });
document.getElementById("queryCompromisedToHighValue").onclick = () =>
  runMarkingPathsQuery("compromised_to_high_value");
document.getElementById("queryBlastCompromised").onclick = () => runMarkingPathsQuery("blast_compromised");
document.getElementById("queryPathsToHighValue").onclick = () => runMarkingPathsQuery("to_high_value");
document.getElementById("searchMode").onchange = updateTargetFieldsVisibility;

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => switchTab(tab.dataset.tab);
});

document.getElementById("sessions").addEventListener("click", (event) => {
  const li = event.target.closest("li[data-id]");
  if (!li) return;
  loadSession(li.dataset.id);
});

document.getElementById("sessions").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const li = event.target.closest("li[data-id]");
  if (!li) return;
  event.preventDefault();
  loadSession(li.dataset.id);
});

initNetwork();
updateTargetFieldsVisibility();
initAuth()
  .then(() => Promise.all([loadConnectors(), loadFixturesCatalog(), loadEnrichmentExamples(), refreshEnrichmentLibrary(), refreshSessions({ scope: "recent", limit: 1, autoLoad: true })]))
  .catch(() => Promise.all([loadConnectors(), loadFixturesCatalog(), loadEnrichmentExamples(), refreshEnrichmentLibrary(), refreshSessions({ scope: "recent", limit: 1, autoLoad: true })]));
}
