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
  // Spatial ScopeBoundary / NetworkBoundary bounding boxes (default on).
  showBoundaryBoxes: true,
  boundaries: [],
  boundaryRects: [],
  boxPeeringEdges: [],
  // Active bounding-box drag: { boundaryId, memberIds, lastX, lastY }
  boxDrag: null,
  // swim | diamond | helio | space | hierarchy | sugiyama | force
  layoutMode: "force",
};

const LAYOUT_MODE_IDS = [
  "swim",
  "diamond",
  "helio",
  "space",
  "hierarchy",
  "sugiyama",
  "force",
];

const NODE_COLORS = {
  Principal: { background: "#1f6feb", border: "#58a6ff", highlight: { background: "#388bfd", border: "#79c0ff" } },
  Resource: { background: "#8b2520", border: "#f85149", highlight: { background: "#b62324", border: "#ff7b72" } },
  ComputeContext: { background: "#1a4d2e", border: "#3fb950", highlight: { background: "#238636", border: "#56d364" } },
  ScopeBoundary: { background: "#30363d", border: "#8b949e", highlight: { background: "#484f58", border: "#b1bac4" } },
  NetworkBoundary: { background: "#1c2b3a", border: "#58a6ff", highlight: { background: "#243447", border: "#79c0ff" } },
  PolicyStatement: { background: "#5a3c00", border: "#ffa657", highlight: { background: "#7d4e00", border: "#ffc078" } },
  AttackOutcome: { background: "#7a3a08", border: "#ffa657", highlight: { background: "#9e4b0e", border: "#ffc078" } },
  Unknown: { background: "#21262d", border: "#484f58", highlight: { background: "#30363d", border: "#8b949e" } },
};

/** Stroke/fill colors for spatial boundary boxes, keyed by boundary_kind. */
const BOUNDARY_BOX_STYLES = {
  account: { stroke: "#8b949e", fill: "rgba(139, 148, 158, 0.08)", label: "#c9d1d9" },
  vpc: { stroke: "#58a6ff", fill: "rgba(88, 166, 255, 0.10)", label: "#79c0ff" },
  subnet: { stroke: "#3fb950", fill: "rgba(63, 185, 80, 0.08)", label: "#56d364" },
  environment: { stroke: "#d2a8ff", fill: "rgba(210, 168, 255, 0.08)", label: "#d2a8ff" },
  ou: { stroke: "#ffa657", fill: "rgba(255, 166, 87, 0.08)", label: "#ffc078" },
  cluster: { stroke: "#a371f7", fill: "rgba(163, 113, 247, 0.08)", label: "#d2a8ff" },
  namespace: { stroke: "#39d353", fill: "rgba(57, 211, 83, 0.07)", label: "#56d364" },
  default: { stroke: "#8b949e", fill: "rgba(139, 148, 158, 0.07)", label: "#c9d1d9" },
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

function isBoundaryNode(node) {
  if (!node) return false;
  return (
    node.label === "ScopeBoundary"
    || node.label === "NetworkBoundary"
    || node.concept_type === "ScopeBoundary"
    || node.concept_type === "OrchestrationScope"
    || node.concept_type === "NetworkBoundary"
  );
}

function inferBoundaryKind(node) {
  if (!node) return "default";
  if (node.boundary_kind) return String(node.boundary_kind);
  const native = String(node.native_id || "");
  if (native.startsWith("aws:account:") || node.is_cross_account_boundary) return "account";
  if (native.startsWith("aws:vpc:") || native.includes(":vpc:")) return "vpc";
  if (native.startsWith("aws:subnet:") || native.includes(":subnet:")) return "subnet";
  if (native.startsWith("aws:ou:") || node.ou) return "ou";
  if (node.environment || native.startsWith("aws:scope:")) return "environment";
  if (node.concept_type === "OrchestrationScope") {
    return node.namespace ? "namespace" : "cluster";
  }
  return "default";
}

function isAccountBoundary(node) {
  return inferBoundaryKind(node) === "account"
    || String(node?.native_id || "").startsWith("aws:account:");
}

function graphHasCrossAccountAccess(graph) {
  const edges = graph?.edges || [];
  if (edges.some((edge) => isPeeringNetworkEdge(edge))) return true;
  const accounts = new Set();
  for (const node of graph?.nodes || []) {
    if (isBoundaryNode(node) && isAccountBoundary(node)) {
      const account = node.account_id || String(node.native_id || "").split(":").pop();
      if (account) accounts.add(String(account));
    }
    if (node.account_id) accounts.add(String(node.account_id));
  }
  return accounts.size > 1;
}

/**
 * Build spatial boundary descriptors from HOSTED_IN edges.
 * Account boundaries are omitted unless cross-account access is present.
 */
function buildBoundaryModel(graph) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  const nodeById = graphNodeMap(nodes);
  const showAccounts = graphHasCrossAccountAccess(graph);

  const boundaryNodes = nodes.filter((node) => {
    if (!isBoundaryNode(node)) return false;
    if (isAccountBoundary(node) && !showAccounts) return false;
    return true;
  });
  const boundaryIds = new Set(boundaryNodes.map((n) => n.id));

  const parentOf = new Map(); // childBoundaryId -> parentBoundaryId
  const directMembers = new Map(); // boundaryId -> Set<nodeId>
  for (const b of boundaryNodes) directMembers.set(b.id, new Set());

  for (const edge of edges) {
    if (edge.rel !== "HOSTED_IN") continue;
    if (!boundaryIds.has(edge.dst)) continue;
    if (boundaryIds.has(edge.src)) {
      // Only record parent if the child boundary itself is shown.
      parentOf.set(edge.src, edge.dst);
    } else {
      directMembers.get(edge.dst)?.add(edge.src);
    }
  }

  function collectLeafMembers(boundaryId, seen = new Set()) {
    if (seen.has(boundaryId)) return [];
    seen.add(boundaryId);
    const leaves = [...(directMembers.get(boundaryId) || [])];
    for (const [childId, parentId] of parentOf.entries()) {
      if (parentId === boundaryId) {
        leaves.push(...collectLeafMembers(childId, seen));
      }
    }
    return [...new Set(leaves)];
  }

  function depthOf(boundaryId, seen = new Set()) {
    if (seen.has(boundaryId)) return 0;
    seen.add(boundaryId);
    const parent = parentOf.get(boundaryId);
    return parent ? 1 + depthOf(parent, seen) : 0;
  }

  return boundaryNodes.map((node) => {
    const kind = inferBoundaryKind(node);
    const label = node.display_name || node.name || shortId(node.native_id || node.id);
    return {
      id: node.id,
      kind,
      label,
      parentId: parentOf.get(node.id) || null,
      memberIds: [...(directMembers.get(node.id) || [])],
      leafMemberIds: collectLeafMembers(node.id),
      depth: depthOf(node.id),
      native_id: node.native_id,
      account_id: node.account_id,
    };
  }).sort((a, b) => a.depth - b.depth);
}

/** Collapse VPC_PEERS → boundary → BRIDGES_TO into a single display edge. */
function collapseBoundaryHopEdges(edges, boundaryIds) {
  const kept = [];
  const intoBoundary = [];
  const outOfBoundary = [];

  for (const edge of edges) {
    const srcB = boundaryIds.has(edge.src);
    const dstB = boundaryIds.has(edge.dst);
    if (!srcB && !dstB) {
      kept.push(edge);
      continue;
    }
    if (edge.rel === "HOSTED_IN") continue;
    if (dstB && !srcB && (edge.rel === "VPC_PEERS" || edge.rel === "BRIDGES_TO")) {
      intoBoundary.push(edge);
    } else if (srcB && !dstB && (edge.rel === "VPC_PEERS" || edge.rel === "BRIDGES_TO")) {
      outOfBoundary.push(edge);
    }
    // Drop other edges that terminate on a hidden boundary glyph.
  }

  for (const inn of intoBoundary) {
    const outs = outOfBoundary.filter((out) => out.src === inn.dst);
    if (!outs.length) continue;
    for (const out of outs) {
      kept.push({
        ...inn,
        dst: out.dst,
        rel: inn.rel === "VPC_PEERS" ? "VPC_PEERS" : out.rel,
        _viaBoundary: inn.dst,
        boundary_crossing: true,
        mechanism: inn.mechanism || out.mechanism || "vpc-peering",
        source: inn.source || out.source || "network-enrichment",
      });
    }
  }
  return kept;
}

function isHiddenDisplayNode(node) {
  return (
    !node
    || node.label === "CollectionSession"
    || isBoundaryNode(node)
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
  const boundaries = buildBoundaryModel(graph);
  state.boundaries = boundaries;
  // All boundary glyphs (drawn or account-gated) — never render as nodes.
  const allBoundaryIds = new Set(
    (graph.nodes || []).filter(isBoundaryNode).map((n) => n.id),
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
  const visibleIds = nodeIds;

  // Collapse peering hops through hidden account boundaries, then filter.
  const collapsed = collapseBoundaryHopEdges(graph.edges || [], allBoundaryIds);
  const useBoxPeering = state.showBoundaryBoxes && boundaries.length > 0;
  state.boxPeeringEdges = useBoxPeering
    ? buildBoxPeeringEdges(graph, boundaries, visibleIds, collapsed)
    : [];

  const edges = [];
  for (const edge of collapsed) {
    if (edge.rel === "DISCOVERED") continue;
    if (edge.rel === "HOSTED_IN") continue;
    // When boxes are on, peering is drawn box↔box — drop node-level peering.
    if (useBoxPeering && isPeeringNetworkEdge(edge)) continue;
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

  return {
    nodes,
    edges: compactCapabilityEdges(edges),
    boundaries,
    boxPeeringEdges: state.boxPeeringEdges,
  };
}

/** Map a visible node to its innermost drawable boundary id. */
function nodeToDrawableBoxId(nodeId, drawable) {
  const containing = drawable.filter(
    (b) => (b.leafMemberIds || []).includes(nodeId) || (b.memberIds || []).includes(nodeId),
  );
  if (!containing.length) return null;
  containing.sort((a, b) => b.depth - a.depth);
  // Prefer VPC over account when both contain the node.
  const vpc = containing.find((b) => b.kind === "vpc");
  if (vpc) return vpc.id;
  return containing[0].id;
}

/**
 * Build deduped box↔box peering edges from VPC_PEERS / BRIDGES_TO chains.
 */
function buildBoxPeeringEdges(graph, boundaries, visibleIds, collapsedEdges) {
  const drawable = selectDrawableBoundaries(boundaries, visibleIds);
  if (!drawable.length) return [];
  const drawableIds = new Set(drawable.map((b) => b.id));
  const pairs = new Map();

  function addPair(a, b, props) {
    if (!a || !b || a === b) return;
    if (!drawableIds.has(a) || !drawableIds.has(b)) return;
    const key = a < b ? `${a}|${b}` : `${b}|${a}`;
    if (!pairs.has(key)) {
      pairs.set(key, {
        src: a,
        dst: b,
        rel: "VPC_PEERS",
        mechanism: props?.mechanism || "vpc-peering",
        source: props?.source || "network-enrichment",
      });
    }
  }

  // Prefer collapsed compute→compute peering when present.
  for (const edge of collapsedEdges || []) {
    if (!isPeeringNetworkEdge(edge)) continue;
    if (!visibleIds.has(edge.src) || !visibleIds.has(edge.dst)) continue;
    addPair(
      nodeToDrawableBoxId(edge.src, drawable),
      nodeToDrawableBoxId(edge.dst, drawable),
      edge,
    );
  }

  // Also walk raw VPC_PEERS → BRIDGES_TO through hidden account nodes.
  const raw = graph?.edges || [];
  const intoAcct = raw.filter((e) => e.rel === "VPC_PEERS");
  const outOfAcct = raw.filter((e) => e.rel === "BRIDGES_TO");
  for (const inn of intoAcct) {
    const outs = outOfAcct.filter((o) => o.src === inn.dst);
    for (const out of outs) {
      addPair(
        nodeToDrawableBoxId(inn.src, drawable),
        nodeToDrawableBoxId(out.dst, drawable),
        inn,
      );
    }
  }

  return [...pairs.values()];
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
  // Boundary supernodes in force layout — size by packed member grid.
  if (node?._isBox) {
    const count = Math.max(1, node._memberIds?.length || 1);
    const cols = Math.min(count, Math.max(1, Math.ceil(Math.sqrt(count * 1.85))));
    const rows = Math.ceil(count / cols);
    return {
      width: Math.max(120, cols * 130 + 24),
      height: Math.max(72, rows * 72 + 20),
    };
  }
  const wrapped = wrapGraphLabel(shortId(displayName(node || {})));
  const lines = wrapped.split("\n");
  const longest = Math.max(...lines.map((line) => line.length), 4);
  const isPrincipal = (node?.label || "") === "Principal";
  // Sized for vis.js labels (multi-line box text + margin) so spacing
  // accounts for readable text, not just the glyph center.
  return {
    width: isPrincipal ? 72 : Math.min(280, 56 + longest * 8.2),
    height: isPrincipal ? 52 : 36 + lines.length * 18,
  };
}

function buildAdjacency(nodes, edges) {
  const idSet = new Set(nodes.map((n) => n.id));
  const outgoing = new Map();
  const incoming = new Map();
  const undirected = new Map();
  idSet.forEach((id) => {
    outgoing.set(id, []);
    incoming.set(id, []);
    undirected.set(id, []);
  });
  edges.forEach((edge) => {
    if (!idSet.has(edge.src) || !idSet.has(edge.dst) || edge.src === edge.dst) return;
    outgoing.get(edge.src).push(edge.dst);
    incoming.get(edge.dst).push(edge.src);
    undirected.get(edge.src).push(edge.dst);
    undirected.get(edge.dst).push(edge.src);
  });
  return { outgoing, incoming, undirected, idSet };
}

function isHighValueLayoutNode(node) {
  if (!node) return false;
  if (node.is_high_value) return true;
  const concept = node.concept_type || "";
  return concept === "SecretStore" || concept === "RegistryStore";
}

function bfsDistances(seeds, adjacency) {
  const dist = new Map();
  const queue = [];
  for (const id of seeds) {
    if (!adjacency.has(id)) continue;
    dist.set(id, 0);
    queue.push(id);
  }
  while (queue.length) {
    const id = queue.shift();
    const d = dist.get(id) ?? 0;
    for (const nbr of adjacency.get(id) || []) {
      if (dist.has(nbr)) continue;
      dist.set(nbr, d + 1);
      queue.push(nbr);
    }
  }
  return dist;
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

/**
 * Rank nodes for an attack-path reading: left = start / compromised (steps out),
 * right = high-value sinks. Uses forward distance from roots and reverse
 * distance from sinks so intermediates sit between them.
 */
function assignLayoutLevels(nodes, edges, rootId) {
  const { outgoing, incoming, undirected, idSet } = buildAdjacency(nodes, edges);
  const roots = pickLayoutRoots(nodes, rootId, idSet);
  let sinks = nodes.filter((n) => idSet.has(n.id) && isHighValueLayoutNode(n)).map((n) => n.id);
  if (!sinks.length) {
    // Fall back to natural sinks: resources / compute with no (or few) outs.
    sinks = nodes
      .filter((n) => idSet.has(n.id) && n.label !== "Principal")
      .sort((a, b) => (outgoing.get(a.id)?.length || 0) - (outgoing.get(b.id)?.length || 0))
      .slice(0, Math.max(1, Math.ceil(nodes.length * 0.15)))
      .map((n) => n.id);
  }
  if (!sinks.length && nodes.length) sinks = [nodes[nodes.length - 1].id];

  const fromRoot = bfsDistances(roots, outgoing);
  const toSink = bfsDistances(sinks, incoming);

  // Fill gaps via undirected BFS so isolated-but-connected nodes still rank.
  const fromRootU = bfsDistances(roots, undirected);
  const toSinkU = bfsDistances(sinks, undirected);

  const scores = new Map();
  let maxScore = 0;
  for (const node of nodes) {
    if (!idSet.has(node.id)) continue;
    const forward = fromRoot.has(node.id) ? fromRoot.get(node.id) : fromRootU.get(node.id);
    const backward = toSink.has(node.id) ? toSink.get(node.id) : toSinkU.get(node.id);
    let score;
    if (forward !== undefined && backward !== undefined) {
      // 0 at start, 1 at high-value.
      score = forward / Math.max(1, forward + backward);
    } else if (forward !== undefined) {
      score = 0.35 + forward * 0.08;
    } else if (backward !== undefined) {
      score = 0.65 - backward * 0.08;
    } else {
      score = 0.5;
    }
    if (roots.includes(node.id)) score = Math.min(score, 0.05);
    if (sinks.includes(node.id) || isHighValueLayoutNode(node)) score = Math.max(score, 0.92);
    scores.set(node.id, score);
    maxScore = Math.max(maxScore, score);
  }

  // Bucket continuous scores into a modest number of ranks (readable columns).
  const targetLayers = Math.max(4, Math.min(10, Math.round(Math.sqrt(nodes.length) * 1.35)));
  const levels = new Map();
  for (const [id, score] of scores.entries()) {
    const level = Math.min(
      targetLayers - 1,
      Math.max(0, Math.round(score * (targetLayers - 1))),
    );
    levels.set(id, level);
  }

  // Ensure roots occupy the leftmost rank and sinks the rightmost when present.
  for (const id of roots) {
    if (levels.has(id)) levels.set(id, 0);
  }
  const maxLevel = Math.max(0, ...levels.values());
  for (const id of sinks) {
    if (levels.has(id)) levels.set(id, maxLevel);
  }

  return { levels, roots, sinks };
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

function enforceMinSpacing(positions, nodes, { iterations = 48, pads = null } = {}) {
  if (!positions || !nodes?.length) return positions;
  const nodeById = graphNodeMap(nodes);
  const ids = nodes.map((n) => n.id).filter((id) => positions[id]);
  // Clearance around vis.js dots / labeled boxes (includes label + margin).
  const padXY = pads || { x: 48, y: 36 };

  for (let iter = 0; iter < iterations; iter += 1) {
    let moved = false;
    for (let i = 0; i < ids.length; i += 1) {
      for (let j = i + 1; j < ids.length; j += 1) {
        const a = ids[i];
        const b = ids[j];
        const fa = estimateNodeFootprint(nodeById.get(a));
        const fb = estimateNodeFootprint(nodeById.get(b));
        const minDx = (fa.width + fb.width) / 2 + padXY.x;
        const minDy = (fa.height + fb.height) / 2 + padXY.y;
        const pa = positions[a];
        const pb = positions[b];
        const dx = pb.x - pa.x;
        const dy = pb.y - pa.y;
        const adx = Math.abs(dx);
        const ady = Math.abs(dy);
        if (adx >= minDx || ady >= minDy) continue;
        // Separating axis: push primarily along the smaller penetration.
        const penX = minDx - adx;
        const penY = minDy - ady;
        if (penX < penY) {
          const push = (penX / 2) * (dx === 0 ? (i % 2 ? 1 : -1) : Math.sign(dx) || 1);
          pa.x -= push;
          pb.x += push;
        } else {
          const push = (penY / 2) * (dy === 0 ? (i % 2 ? 1 : -1) : Math.sign(dy) || 1);
          pa.y -= push;
          pb.y += push;
        }
        moved = true;
      }
    }
    if (!moved) break;
  }
  return positions;
}

/**
 * Soft edge attraction: pull connected nodes toward a readable ideal distance.
 * Unhosted nodes (principals / anything outside a boundary box) move more than
 * their boxed neighbors so they tuck in beside the box without dragging it.
 */
function pullConnectedNeighbors(positions, nodes, edges, {
  iterations = 10,
  strength = 0.12,
  unhostedStrength = 0.28,
  idealPad = 130,
} = {}) {
  if (!positions || !nodes?.length || !edges?.length) return positions;

  const nodeById = graphNodeMap(nodes);
  const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
  const { undirected } = buildAdjacency(nodes, edges);
  const drawable = state.showBoundaryBoxes
    ? selectDrawableBoundaries(state.boundaries || [], visibleIds)
    : [];

  const pairs = [];
  const seen = new Set();
  for (const [src, dsts] of undirected.entries()) {
    if (!visibleIds.has(src)) continue;
    for (const dst of dsts) {
      if (!visibleIds.has(dst)) continue;
      const key = src < dst ? `${src}|${dst}` : `${dst}|${src}`;
      if (seen.has(key)) continue;
      seen.add(key);
      pairs.push([src, dst]);
    }
  }
  if (!pairs.length) return positions;

  for (let iter = 0; iter < iterations; iter += 1) {
    for (const [a, b] of pairs) {
      const pa = positions[a];
      const pb = positions[b];
      const fa = estimateNodeFootprint(nodeById.get(a));
      const fb = estimateNodeFootprint(nodeById.get(b));
      // Keep a generous readable gap — attraction should not pack labels.
      const ideal = Math.max(
        210,
        (fa.width + fb.width) / 2 + idealPad,
        (fa.height + fb.height) / 2 + idealPad * 0.7,
      );

      const dx = pb.x - pa.x;
      const dy = pb.y - pa.y;
      const dist = Math.hypot(dx, dy) || 1;
      if (dist <= ideal) continue;

      const excess = dist - ideal;
      const ux = dx / dist;
      const uy = dy / dist;
      const aUnhosted = !nodeToDrawableBoxId(a, drawable);
      const bUnhosted = !nodeToDrawableBoxId(b, drawable);

      let pullA = strength * 0.5;
      let pullB = strength * 0.5;
      if (aUnhosted && !bUnhosted) {
        pullA = unhostedStrength;
        pullB = strength * 0.15;
      } else if (bUnhosted && !aUnhosted) {
        pullB = unhostedStrength;
        pullA = strength * 0.15;
      } else if (aUnhosted && bUnhosted) {
        pullA = unhostedStrength * 0.5;
        pullB = unhostedStrength * 0.5;
      }

      pa.x += ux * excess * pullA;
      pa.y += uy * excess * pullA;
      pb.x -= ux * excess * pullB;
      pb.y -= uy * excess * pullB;
    }
  }
  return positions;
}

/**
 * Mild untangle: when two edges cross between roughly layered columns,
 * nudge their left/right endpoints apart on Y. Caps movement so dense
 * graphs (e.g. AWSGoat) cannot explode the canvas.
 */
function untangleEdgeCrossings(positions, edges, { iterations = 6, nudge = 14, maxShift = 80 } = {}) {
  if (!positions || !edges?.length) return positions;
  const list = edges.filter((e) => (
    e.src !== e.dst && positions[e.src] && positions[e.dst]
  ));
  if (list.length < 2) return positions;

  const shifted = new Map();
  const addShift = (point, dy) => {
    // Cap cumulative Y drift per position object.
    const key = point;
    const prev = shifted.get(key) || 0;
    const next = Math.max(-maxShift, Math.min(maxShift, prev + dy));
    const applied = next - prev;
    if (!applied) return 0;
    shifted.set(key, next);
    point.y += applied;
    return applied;
  };

  for (let iter = 0; iter < iterations; iter += 1) {
    let moved = false;
    for (let i = 0; i < list.length; i += 1) {
      for (let j = i + 1; j < list.length; j += 1) {
        const e1 = list[i];
        const e2 = list[j];
        if (new Set([e1.src, e1.dst, e2.src, e2.dst]).size < 4) continue;

        const a = positions[e1.src];
        const b = positions[e1.dst];
        const c = positions[e2.src];
        const d = positions[e2.dst];

        const left1 = a.x <= b.x ? a : b;
        const right1 = a.x <= b.x ? b : a;
        const left2 = c.x <= d.x ? c : d;
        const right2 = c.x <= d.x ? d : c;

        // Only consider near-layered pairs (similar left X / right X).
        if (Math.abs(left1.x - left2.x) > 90) continue;
        if (Math.abs(right1.x - right2.x) > 90) continue;
        if ((left1.y - left2.y) * (right1.y - right2.y) >= 0) continue;

        const step = nudge * (1 - iter / (iterations + 1));
        if (left1.y <= left2.y) {
          if (addShift(left1, -step) || addShift(left2, step)) moved = true;
        } else if (addShift(left1, step) || addShift(left2, -step)) {
          moved = true;
        }
        if (right1.y <= right2.y) {
          if (addShift(right1, -step * 0.5) || addShift(right2, step * 0.5)) moved = true;
        } else if (addShift(right1, step * 0.5) || addShift(right2, -step * 0.5)) {
          moved = true;
        }
      }
    }
    if (!moved) break;
  }
  return positions;
}

function placeRankedBand(ids, levels, origin, opts = {}) {
  const layerGapX = opts.layerGapX || 240;
  const bandHalfH = opts.bandHalfH || 120;
  const positions = {};
  if (!ids.length) return { positions, width: 0, height: 0 };

  const byLevel = new Map();
  ids.forEach((id) => {
    const lvl = levels.get(id) ?? 0;
    if (!byLevel.has(lvl)) byLevel.set(lvl, []);
    byLevel.get(lvl).push(id);
  });
  const orderedLevels = [...byLevel.keys()].sort((a, b) => a - b);
  orderedLevels.forEach((level, layerIndex) => {
    const layerIds = byLevel.get(level);
    const x = origin.x + layerIndex * layerGapX;
    if (layerIds.length === 1) {
      positions[layerIds[0]] = { x, y: origin.y };
      return;
    }
    const gap = Math.min(110, (bandHalfH * 2) / Math.max(1, layerIds.length - 1));
    const startY = origin.y - ((layerIds.length - 1) * gap) / 2;
    layerIds
      .slice()
      .sort((a, b) => String(a).localeCompare(String(b)))
      .forEach((id, index) => {
        positions[id] = { x, y: startY + index * gap };
      });
  });

  const xs = Object.values(positions).map((p) => p.x);
  const ys = Object.values(positions).map((p) => p.y);
  return {
    positions,
    width: Math.max(120, Math.max(...xs) - Math.min(...xs) + 160),
    height: Math.max(80, Math.max(...ys) - Math.min(...ys) + 100),
  };
}

function layoutBounds(positions, nodes) {
  const ids = nodes.map((n) => n.id).filter((id) => positions[id]);
  if (!ids.length) return { width: 0, height: 0, minX: 0, minY: 0 };
  const feet = ids.map((id) => estimateNodeFootprint(nodes.find((n) => n.id === id)));
  const xs = ids.map((id) => positions[id].x);
  const ys = ids.map((id) => positions[id].y);
  const maxHalfW = Math.max(40, ...feet.map((f) => f.width / 2));
  const maxHalfH = Math.max(20, ...feet.map((f) => f.height / 2));
  const minX = Math.min(...xs) - maxHalfW;
  const maxX = Math.max(...xs) + maxHalfW;
  const minY = Math.min(...ys) - maxHalfH;
  const maxY = Math.max(...ys) + maxHalfH;
  return {
    width: Math.max(80, maxX - minX),
    height: Math.max(60, maxY - minY),
    minX,
    minY,
  };
}

/** Classic / diamond LTR attack-path layout for a connected component. */
function layoutConnectedComponent(nodes, edges, rootId, { diamond = true } = {}) {
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
  for (let pass = 0; pass < 4; pass += 1) {
    const nextPrev = new Map();
    orderedLevels.forEach((level) => {
      const ordered = orderLayerByBarycenter(byLevel.get(level) || [], prevY, undirected);
      levelOrder.set(level, ordered);
      ordered.forEach((id, index) => nextPrev.set(id, index));
    });
    prevY = nextPrev;
  }

  const positions = {};
  const layerGapX = 320;
  const baseGapY = 140;
  const layerCount = Math.max(1, orderedLevels.length);
  const maxLayerSize = Math.max(1, ...orderedLevels.map((lvl) => (byLevel.get(lvl) || []).length));
  const peakHalfHeight = Math.max(200, maxLayerSize * baseGapY * 0.62);

  orderedLevels.forEach((level, layerIndex) => {
    const ids = levelOrder.get(level) || byLevel.get(level) || [];
    const t = layerCount === 1 ? 0.5 : layerIndex / (layerCount - 1);
    const envelope = diamond ? Math.sin(Math.PI * t) : 0.55;
    const halfHeight = Math.max(120, 130 + (peakHalfHeight - 130) * (0.3 + 0.7 * envelope));
    const x = layerIndex * layerGapX;

    if (ids.length === 1) {
      positions[ids[0]] = { x, y: 0 };
      return;
    }

    const feet = ids.map((id) => estimateNodeFootprint(nodeById.get(id)));
    const totalWeight = feet.reduce((sum, f) => sum + Math.max(baseGapY, f.height + 56), 0);
    let cursor = -halfHeight;
    const span = halfHeight * 2;
    ids.forEach((id, index) => {
      const weight = Math.max(baseGapY, feet[index].height + 56);
      const step = (weight / totalWeight) * span;
      positions[id] = { x, y: cursor + step / 2 };
      cursor += step;
    });
    const ys = ids.map((id) => positions[id].y);
    const mid = (Math.min(...ys) + Math.max(...ys)) / 2;
    ids.forEach((id) => {
      positions[id].y -= mid;
    });
  });

  enforceMinSpacing(positions, nodes);
  const bounds = layoutBounds(positions, nodes);
  return { positions, ...bounds };
}

function layoutHierarchyComponent(nodes, edges, rootId) {
  return layoutConnectedComponent(nodes, edges, rootId, { diamond: false });
}

function assembleComponentLayouts(nodes, edges, rootId, componentLayoutFn) {
  const nodeById = graphNodeMap(nodes);
  const { undirected } = buildAdjacency(nodes, edges);
  const components = findConnectedComponents(nodes, undirected).sort(
    (a, b) => scoreLayoutComponent(b, nodeById, rootId) - scoreLayoutComponent(a, nodeById, rootId),
  );

  const layouts = components.map((ids) => {
    const idSet = new Set(ids);
    const componentNodes = ids.map((id) => nodeById.get(id)).filter(Boolean);
    const componentEdges = edges.filter((edge) => idSet.has(edge.src) && idSet.has(edge.dst));
    const localRoot = ids.includes(rootId)
      ? rootId
      : pickLayoutRoots(componentNodes, null, idSet)[0];
    return componentLayoutFn(componentNodes, componentEdges, localRoot);
  });

  const positions = {};
  let rowX = 0;
  let rowY = 0;
  let rowHeight = 0;
  const maxRowWidth = 1600;
  const gapX = 160;
  const gapY = 180;

  layouts.forEach((layout) => {
    if (rowX > 0 && rowX + layout.width > maxRowWidth) {
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

  enforceMinSpacing(positions, nodes);
  return positions;
}

function layoutSwim(nodes, edges, rootId) {
  // Swim = attack-path layout + mild same-boundary Y clustering.
  // Boxes themselves are live hulls drawn later — not layout primaries.
  const positions = assembleComponentLayouts(nodes, edges, rootId, (n, e, r) =>
    layoutConnectedComponent(n, e, r, { diamond: true }));
  if (state.showBoundaryBoxes && state.boundaries?.length) {
    packBoundaryClusters(positions, nodes, state.boundaries);
  } else {
    enforceMinSpacing(positions, nodes);
  }
  return { positions, boundaryRects: [] };
}

function layoutHelio(nodes, edges, rootId) {
  const nodeById = graphNodeMap(nodes);
  const { undirected } = buildAdjacency(nodes, edges);
  const sinks = nodes.filter((n) => isHighValueLayoutNode(n));
  const centers = sinks.length
    ? sinks.map((n) => n.id)
    : [rootId || nodes[0]?.id].filter(Boolean);
  const dist = bfsDistances(centers, undirected);
  nodes.forEach((n) => {
    if (!dist.has(n.id)) dist.set(n.id, 3);
  });

  const byRing = new Map();
  for (const node of nodes) {
    const ring = dist.get(node.id) || 0;
    if (!byRing.has(ring)) byRing.set(ring, []);
    byRing.get(ring).push(node.id);
  }

  const positions = {};
  const ringGap = 220;
  // Seed angle by boundary membership for readable sectors.
  const drawable = selectDrawableBoundaries(state.boundaries || [], new Set(nodes.map((n) => n.id)));
  const angleSeed = (id) => {
    const box = nodeToDrawableBoxId(id, drawable);
    if (!box) return id.split("").reduce((s, c) => s + c.charCodeAt(0), 0);
    return box.split("").reduce((s, c) => s + c.charCodeAt(0), 0);
  };

  [...byRing.keys()].sort((a, b) => a - b).forEach((ring) => {
    const ids = byRing.get(ring).sort((a, b) => angleSeed(a) - angleSeed(b) || String(a).localeCompare(String(b)));
    if (ring === 0) {
      ids.forEach((id, index) => {
        positions[id] = {
          x: (index - (ids.length - 1) / 2) * 140,
          y: (index % 2) * 40,
        };
      });
      return;
    }
    const radius = ring * ringGap;
    ids.forEach((id, index) => {
      const angle = (2 * Math.PI * index) / ids.length - Math.PI / 2;
      positions[id] = {
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      };
    });
  });

  enforceMinSpacing(positions, nodes);
  return { positions, boundaryRects: [] };
}

function layoutSpace(nodes, edges, rootId) {
  const nodeById = graphNodeMap(nodes);
  const { undirected } = buildAdjacency(nodes, edges);
  const components = findConnectedComponents(nodes, undirected).sort(
    (a, b) => scoreLayoutComponent(b, nodeById, rootId) - scoreLayoutComponent(a, nodeById, rootId),
  );

  const positions = {};
  const cellGap = 48;
  let cursorX = 0;
  let cursorY = 0;
  let rowH = 0;
  const maxRowW = 1800;

  components.forEach((ids) => {
    const componentNodes = ids.map((id) => nodeById.get(id)).filter(Boolean);
    const cols = Math.max(1, Math.ceil(Math.sqrt(ids.length * 1.6)));
    const gapX = 200;
    const gapY = 110;
    const sorted = [...ids].sort((a, b) => {
      const na = nodeById.get(a);
      const nb = nodeById.get(b);
      const pa = na?.is_caller ? 0 : isHighValueLayoutNode(na) ? 2 : 1;
      const pb = nb?.is_caller ? 0 : isHighValueLayoutNode(nb) ? 2 : 1;
      if (pa !== pb) return pa - pb;
      return String(a).localeCompare(String(b));
    });
    const local = {};
    sorted.forEach((id, index) => {
      const col = index % cols;
      const row = Math.floor(index / cols);
      local[id] = { x: col * gapX, y: row * gapY };
    });
    enforceMinSpacing(local, componentNodes);
    const xs = Object.values(local).map((p) => p.x);
    const ys = Object.values(local).map((p) => p.y);
    const w = Math.max(...xs) - Math.min(...xs) + 180;
    const h = Math.max(...ys) - Math.min(...ys) + 140;
    if (cursorX > 0 && cursorX + w > maxRowW) {
      cursorX = 0;
      cursorY += rowH + cellGap;
      rowH = 0;
    }
    const minX = Math.min(...xs);
    const minY = Math.min(...ys);
    Object.entries(local).forEach(([id, point]) => {
      positions[id] = {
        x: point.x - minX + cursorX,
        y: point.y - minY + cursorY,
      };
    });
    cursorX += w + cellGap;
    rowH = Math.max(rowH, h);
  });

  enforceMinSpacing(positions, nodes);
  return { positions, boundaryRects: [] };
}

/**
 * Sugiyama-style layered digraph: rank from attack roots → sinks, barycenter
 * crossing reduction (forward + backward), then straight columns.
 */
function layoutSugiyamaComponent(nodes, edges, rootId) {
  if (!nodes.length) {
    return { positions: {}, width: 0, height: 0, minX: 0, minY: 0 };
  }

  const nodeById = graphNodeMap(nodes);
  const { undirected, incoming } = buildAdjacency(nodes, edges);
  const { levels } = assignLayoutLevels(nodes, edges, rootId);

  const byLevel = new Map();
  levels.forEach((level, id) => {
    if (!byLevel.has(level)) byLevel.set(level, []);
    byLevel.get(level).push(id);
  });
  const orderedLevels = [...byLevel.keys()].sort((a, b) => a - b);

  const levelOrder = new Map();
  orderedLevels.forEach((level) => {
    levelOrder.set(
      level,
      (byLevel.get(level) || []).slice().sort((a, b) => String(a).localeCompare(String(b))),
    );
  });

  // Crossing reduction: alternate barycenter from left neighbors and right neighbors.
  for (let pass = 0; pass < 10; pass += 1) {
    const forward = pass % 2 === 0;
    if (forward) {
      let prevPos = new Map();
      orderedLevels.forEach((level) => {
        const ordered = orderLayerByBarycenter(levelOrder.get(level) || [], prevPos, undirected);
        levelOrder.set(level, ordered);
        prevPos = new Map(ordered.map((id, index) => [id, index]));
      });
    } else {
      let nextPos = new Map();
      for (let li = orderedLevels.length - 1; li >= 0; li -= 1) {
        const level = orderedLevels[li];
        const ordered = orderLayerByBarycenter(levelOrder.get(level) || [], nextPos, undirected);
        levelOrder.set(level, ordered);
        nextPos = new Map(ordered.map((id, index) => [id, index]));
      }
    }
  }

  // Optional median fine-tune using incoming neighbors (directed sense).
  const medianOrder = (layerIds, refPos, neighborsOf) => {
    if (!refPos?.size) return layerIds.slice();
    return layerIds.slice().sort((a, b) => {
      const med = (id) => {
        const nbrs = (neighborsOf.get(id) || [])
          .filter((n) => refPos.has(n))
          .map((n) => refPos.get(n))
          .sort((x, y) => x - y);
        if (!nbrs.length) return refPos.has(id) ? refPos.get(id) : Number.POSITIVE_INFINITY;
        return nbrs[Math.floor(nbrs.length / 2)];
      };
      const diff = med(a) - med(b);
      if (diff !== 0) return diff;
      return String(a).localeCompare(String(b));
    });
  };

  let prev = new Map((levelOrder.get(orderedLevels[0]) || []).map((id, i) => [id, i]));
  for (let li = 1; li < orderedLevels.length; li += 1) {
    const level = orderedLevels[li];
    const ordered = medianOrder(levelOrder.get(level) || [], prev, incoming);
    levelOrder.set(level, ordered);
    prev = new Map(ordered.map((id, i) => [id, i]));
  }

  const positions = {};
  const layerGapX = 300;
  const baseGapY = 128;

  orderedLevels.forEach((level, layerIndex) => {
    const ids = levelOrder.get(level) || [];
    const x = layerIndex * layerGapX;
    if (!ids.length) return;
    if (ids.length === 1) {
      positions[ids[0]] = { x, y: 0 };
      return;
    }
    const feet = ids.map((id) => estimateNodeFootprint(nodeById.get(id)));
    const gaps = feet.map((f) => Math.max(baseGapY, f.height + 48));
    const total = gaps.reduce((s, g) => s + g, 0);
    let cursor = -total / 2;
    ids.forEach((id, index) => {
      positions[id] = { x, y: cursor + gaps[index] / 2 };
      cursor += gaps[index];
    });
  });

  enforceMinSpacing(positions, nodes);
  const bounds = layoutBounds(positions, nodes);
  return { positions, ...bounds };
}

function layoutSugiyama(nodes, edges, rootId) {
  return {
    positions: assembleComponentLayouts(nodes, edges, rootId, layoutSugiyamaComponent),
    boundaryRects: [],
  };
}

/**
 * Force-directed (Fruchterman–Reingold style) for organic clustering.
 * Tuned compact: stronger edge springs + mild gravity so far leaves
 * don't drift to the outer rim.
 */
function layoutForceComponent(nodes, edges, rootId) {
  if (!nodes.length) {
    return { positions: {}, width: 0, height: 0, minX: 0, minY: 0 };
  }

  const ids = nodes.map((n) => n.id);
  const n = ids.length;
  const positions = {};
  const seedR = Math.max(100, Math.sqrt(n) * 34);

  ids.forEach((id, index) => {
    const angle = (2 * Math.PI * index) / Math.max(1, n) - Math.PI / 2;
    const hash = id.split("").reduce((s, c) => s + c.charCodeAt(0), 0);
    positions[id] = {
      x: Math.cos(angle) * seedR + (hash % 17) - 8,
      y: Math.sin(angle) * seedR + ((hash * 5) % 17) - 8,
    };
  });
  if (rootId && positions[rootId]) {
    positions[rootId] = { x: -seedR * 0.25, y: 0 };
  }

  // Smaller ideal length → tighter overall diameter.
  const area = Math.max(320, n) * 6800;
  const k = Math.sqrt(area / Math.max(1, n));
  const attractBoost = 1.85;
  const gravity = 0.045;
  const iterations = Math.min(130, 45 + Math.floor(n * 1.1));
  let temperature = seedR * 0.38;

  const uniquePairs = [];
  const seen = new Set();
  for (const edge of edges) {
    if (!positions[edge.src] || !positions[edge.dst] || edge.src === edge.dst) continue;
    const key = edge.src < edge.dst ? `${edge.src}|${edge.dst}` : `${edge.dst}|${edge.src}`;
    if (seen.has(key)) continue;
    seen.add(key);
    uniquePairs.push([edge.src, edge.dst]);
  }

  for (let iter = 0; iter < iterations; iter += 1) {
    const disp = Object.fromEntries(ids.map((id) => [id, { x: 0, y: 0 }]));

    for (let i = 0; i < n; i += 1) {
      for (let j = i + 1; j < n; j += 1) {
        const a = ids[i];
        const b = ids[j];
        let dx = positions[a].x - positions[b].x;
        let dy = positions[a].y - positions[b].y;
        const dist = Math.hypot(dx, dy) || 0.01;
        const force = (k * k) / dist * (dist > k * 2.5 ? 0.55 : 1);
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        disp[a].x += dx;
        disp[a].y += dy;
        disp[b].x -= dx;
        disp[b].y -= dy;
      }
    }

    for (const [src, dst] of uniquePairs) {
      let dx = positions[src].x - positions[dst].x;
      let dy = positions[src].y - positions[dst].y;
      const dist = Math.hypot(dx, dy) || 0.01;
      const force = ((dist * dist) / k) * attractBoost;
      dx = (dx / dist) * force;
      dy = (dy / dist) * force;
      disp[src].x -= dx;
      disp[src].y -= dy;
      disp[dst].x += dx;
      disp[dst].y += dy;
    }

    let cx = 0;
    let cy = 0;
    for (const id of ids) {
      cx += positions[id].x;
      cy += positions[id].y;
    }
    cx /= n;
    cy /= n;
    for (const id of ids) {
      disp[id].x += (cx - positions[id].x) * gravity;
      disp[id].y += (cy - positions[id].y) * gravity;
    }

    for (const id of ids) {
      const mag = Math.hypot(disp[id].x, disp[id].y) || 1;
      let scale = Math.min(mag, temperature) / mag;
      if (id === rootId) scale *= 0.12;
      positions[id].x += disp[id].x * scale;
      positions[id].y += disp[id].y * scale;
    }
    temperature *= 0.93;
  }

  let cx = 0;
  let cy = 0;
  for (const id of ids) {
    cx += positions[id].x;
    cy += positions[id].y;
  }
  cx /= n;
  cy /= n;
  const radii = ids.map((id) => Math.hypot(positions[id].x - cx, positions[id].y - cy))
    .sort((a, b) => a - b);
  const medianR = radii[Math.floor(radii.length / 2)] || seedR;
  const maxR = Math.max(medianR * 2.05, k * 3.2);
  for (const id of ids) {
    if (id === rootId) continue;
    const dx = positions[id].x - cx;
    const dy = positions[id].y - cy;
    const r = Math.hypot(dx, dy);
    if (r <= maxR || r < 1) continue;
    const scale = maxR / r;
    positions[id].x = cx + dx * scale;
    positions[id].y = cy + dy * scale;
  }

  enforceMinSpacing(positions, nodes);
  const bounds = layoutBounds(positions, nodes);
  return { positions, ...bounds };
}

/** Compact grid of members centered on (cx, cy) — prefer wide/short packs. */
function packMembersAround(positions, memberIds, nodes, cx, cy) {
  const nodeById = graphNodeMap(nodes);
  if (!memberIds.length) return;
  if (memberIds.length === 1) {
    positions[memberIds[0]] = { x: cx, y: cy };
    return;
  }

  const ordered = [...memberIds].sort((a, b) => String(a).localeCompare(String(b)));
  const feet = ordered.map((id) => {
    const src = nodeById.get(id);
    return estimateNodeFootprint(src?._raw || src || { id });
  });
  const gapX = Math.max(...feet.map((f) => f.width)) + 24;
  const gapY = Math.max(...feet.map((f) => f.height)) + 16;

  const n = ordered.length;
  // Bias columns so boxes stay short rather than tall towers.
  let cols = Math.min(n, Math.max(1, Math.ceil(Math.sqrt(n * 1.85))));
  let rows = Math.ceil(n / cols);
  while (cols < n && rows * gapY > cols * gapX * 0.9) {
    cols += 1;
    rows = Math.ceil(n / cols);
  }

  const width = (cols - 1) * gapX;
  const height = (rows - 1) * gapY;
  ordered.forEach((id, index) => {
    const col = index % cols;
    const row = Math.floor(index / cols);
    positions[id] = {
      x: cx - width / 2 + col * gapX,
      y: cy - height / 2 + row * gapY,
    };
  });

  // Resolve only true overlaps — don't inflate the pack with large pads.
  const memberNodes = ordered.map((id) => nodeById.get(id)).filter(Boolean);
  const local = Object.fromEntries(ordered.map((id) => [id, { ...positions[id] }]));
  enforceMinSpacing(local, memberNodes, { iterations: 16, pads: { x: 10, y: 8 } });
  let lx = 0;
  let ly = 0;
  for (const id of ordered) {
    lx += local[id].x;
    ly += local[id].y;
  }
  lx /= ordered.length;
  ly /= ordered.length;
  for (const id of ordered) {
    positions[id] = {
      x: local[id].x - lx + cx,
      y: local[id].y - ly + cy,
    };
  }
}

/**
 * Pack units for force+box layout:
 * - leaf boxes (subnets): all their members
 * - parent boxes (VPCs with child subnets): direct-only members (compute not in a subnet)
 */
function collectBoundaryPackUnits(drawable, visibleIds) {
  const units = [];
  for (const box of drawable || []) {
    const hasChild = (drawable || []).some((child) => child.parentId === box.id);
    if (!hasChild) {
      const members = (box.leafMemberIds || []).filter((id) => visibleIds.has(id));
      if (!members.length) continue;
      units.push({
        metaId: `__box__:${box.id}`,
        boxId: box.id,
        label: box.label || box.id,
        members,
      });
      continue;
    }
    const direct = (box.memberIds || []).filter((id) => visibleIds.has(id));
    if (!direct.length) continue;
    units.push({
      metaId: `__box__:${box.id}:direct`,
      boxId: box.id,
      label: box.label || box.id,
      members: direct,
    });
  }
  return units;
}

function rePackBoundaryUnits(positions, nodes, units) {
  for (const unit of units) {
    const members = (unit.members || []).filter((id) => positions[id]);
    if (!members.length) continue;
    let cx = 0;
    let cy = 0;
    for (const id of members) {
      cx += positions[id].x;
      cy += positions[id].y;
    }
    cx /= members.length;
    cy /= members.length;
    packMembersAround(positions, members, nodes, cx, cy);
  }
}

/**
 * VPC-direct compute (in the VPC, not in a subnet): compact strip just above
 * subnet content — never inside a subnet box.
 */
function placeVpcDirectComputeAtTop(positions, nodes, boundaries) {
  if (!positions || !nodes?.length || !boundaries?.length) return positions;

  const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
  const drawable = selectDrawableBoundaries(boundaries, visibleIds);
  const nodeById = graphNodeMap(nodes);
  const vpcs = drawable.filter((b) => b.kind === "vpc");

  for (const vpc of vpcs) {
    const direct = (vpc.memberIds || []).filter((id) => visibleIds.has(id) && positions[id]);
    if (!direct.length) continue;

    const childSubnets = drawable.filter(
      (c) => c.parentId === vpc.id && c.kind === "subnet",
    );

    let subnetMinX = Infinity;
    let subnetMaxX = -Infinity;
    let subnetMinY = Infinity;
    let anySubnetMember = false;

    for (const sub of childSubnets) {
      for (const id of sub.leafMemberIds || []) {
        const p = positions[id];
        if (!p) continue;
        const src = nodeById.get(id);
        const foot = estimateNodeFootprint(src?._raw || src || { id });
        anySubnetMember = true;
        subnetMinX = Math.min(subnetMinX, p.x - foot.width / 2);
        subnetMaxX = Math.max(subnetMaxX, p.x + foot.width / 2);
        subnetMinY = Math.min(subnetMinY, p.y - foot.height / 2);
      }
    }

    if (!anySubnetMember) {
      let cx = 0;
      let cy = 0;
      for (const id of direct) {
        cx += positions[id].x;
        cy += positions[id].y;
      }
      cx /= direct.length;
      cy /= direct.length;
      packMembersAround(positions, direct, nodes, cx, cy);
      continue;
    }

    const maxDirectH = Math.max(
      ...direct.map((id) => {
        const src = nodeById.get(id);
        return estimateNodeFootprint(src?._raw || src || { id }).height;
      }),
      40,
    );
    const cx = (subnetMinX + subnetMaxX) / 2;
    // Sit a little above the subnet cluster — readable gap, not mid-VPC void.
    const bandY = subnetMinY - 24 - maxDirectH / 2;
    packMembersAround(positions, direct, nodes, cx, bandY);

    // Hard guarantee: not inside any child subnet hull.
    const subnetHulls = computeBoundaryHullsFromPositions(positions, nodes, boundaries)
      .filter((h) => childSubnets.some((s) => s.id === h.id));
    for (const id of direct) {
      const p = positions[id];
      if (!p) continue;
      const src = nodeById.get(id);
      const foot = estimateNodeFootprint(src?._raw || src || { id });
      const clearance = 20 + foot.height / 2;
      for (const rect of subnetHulls) {
        const inside = (
          p.x >= rect.x
          && p.x <= rect.x + rect.w
          && p.y >= rect.y
          && p.y <= rect.y + rect.h
        );
        if (!inside) continue;
        p.y = rect.y - clearance;
      }
    }
  }
  return positions;
}

function countCrossBoxBonds(membersA, membersB, undirected) {
  if (!membersA?.length || !membersB?.length || !undirected) return 0;
  const inB = new Set(membersB);
  let count = 0;
  for (const a of membersA) {
    for (const nbr of undirected.get(a) || []) {
      if (inB.has(nbr)) count += 1;
    }
  }
  return count;
}

/**
 * Separate drawable boxes of one kind that actually overlap.
 * When boxes share edges, push along the bond axis so neighbors stay adjacent.
 */
function separateBoundaryKindPreferNoOverlap(
  positions,
  nodes,
  boundaries,
  kind,
  { gap = 40, iterations = 64, edges = null } = {},
) {
  if (!positions || !nodes?.length || !boundaries?.length || !kind) return positions;

  const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
  const ofKind = selectDrawableBoundaries(boundaries, visibleIds)
    .filter((b) => b.kind === kind);
  if (ofKind.length < 2) return positions;

  const membersOf = new Map(
    ofKind.map((b) => [
      b.id,
      (b.leafMemberIds || []).filter((id) => visibleIds.has(id)),
    ]),
  );
  const undirected = edges?.length
    ? buildAdjacency(nodes, edges).undirected
    : null;

  const translate = (boxId, dx, dy) => {
    for (const id of membersOf.get(boxId) || []) {
      if (!positions[id]) continue;
      positions[id].x += dx;
      positions[id].y += dy;
    }
  };

  for (let iter = 0; iter < iterations; iter += 1) {
    const hulls = computeBoundaryHullsFromPositions(positions, nodes, boundaries)
      .filter((h) => h.kind === kind);
    if (hulls.length < 2) break;

    let best = null;
    for (let i = 0; i < hulls.length; i += 1) {
      for (let j = i + 1; j < hulls.length; j += 1) {
        const a = hulls[i];
        const b = hulls[j];
        const ox = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
        const oy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
        if (ox <= 0 || oy <= 0) continue;
        const bonds = countCrossBoxBonds(
          membersOf.get(a.id), membersOf.get(b.id), undirected,
        );
        // Prefer resolving bonded overlaps first; then largest area.
        const score = bonds * 1e9 + ox * oy;
        if (!best || score > best.score) best = { a, b, ox, oy, bonds, score };
      }
    }
    if (!best) break;

    const { a, b, ox, oy, bonds } = best;
    const acx = a.x + a.w / 2;
    const acy = a.y + a.h / 2;
    const bcx = b.x + b.w / 2;
    const bcy = b.y + b.h / 2;
    // Bonded boxes: separate along the center axis so they remain neighbors.
    // Unrelated boxes: prefer the cheaper (smaller) overlap axis.
    const preferHorizontal = bonds > 0
      ? Math.abs(bcx - acx) >= Math.abs(bcy - acy)
      : oy > ox;

    if (!preferHorizontal) {
      const push = oy + gap;
      if (acy <= bcy) translate(b.id, 0, push);
      else translate(a.id, 0, push);
    } else {
      const push = ox + gap;
      if (acx <= bcx) translate(b.id, push, 0);
      else translate(a.id, push, 0);
    }
  }
  return positions;
}

/**
 * Translate whole boxes toward each other when members share edges, stopping
 * before hulls overlap — keeps related clusters near without shredding packs.
 */
function attractBoundaryNeighbors(
  positions,
  nodes,
  edges,
  boundaries,
  { iterations = 14, strength = 0.28, gap = 40 } = {},
) {
  if (!positions || !nodes?.length || !edges?.length || !boundaries?.length) {
    return positions;
  }

  const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
  const drawable = selectDrawableBoundaries(boundaries, visibleIds);
  if (drawable.length < 2) return positions;

  const membersOf = new Map(
    drawable.map((b) => [
      b.id,
      (b.leafMemberIds || []).filter((id) => visibleIds.has(id)),
    ]),
  );
  const boxOf = new Map();
  for (const [boxId, members] of membersOf) {
    for (const id of members) boxOf.set(id, boxId);
  }

  const pairBonds = new Map();
  for (const edge of edges) {
    if (!visibleIds.has(edge.src) || !visibleIds.has(edge.dst)) continue;
    const a = boxOf.get(edge.src);
    const b = boxOf.get(edge.dst);
    if (!a || !b || a === b) continue;
    const key = a < b ? `${a}|${b}` : `${b}|${a}`;
    pairBonds.set(key, (pairBonds.get(key) || 0) + 1);
  }
  if (!pairBonds.size) return positions;

  const translate = (boxId, dx, dy) => {
    for (const id of membersOf.get(boxId) || []) {
      if (!positions[id]) continue;
      positions[id].x += dx;
      positions[id].y += dy;
    }
  };

  for (let iter = 0; iter < iterations; iter += 1) {
    const hullById = new Map(
      computeBoundaryHullsFromPositions(positions, nodes, boundaries)
        .map((h) => [h.id, h]),
    );
    let moved = false;

    for (const [key, bonds] of pairBonds) {
      const [idA, idB] = key.split("|");
      const a = hullById.get(idA);
      const b = hullById.get(idB);
      if (!a || !b) continue;

      const ox = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
      const oy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
      if (ox > 0 && oy > 0) continue; // already overlapping — separator owns this

      const acx = a.x + a.w / 2;
      const acy = a.y + a.h / 2;
      const bcx = b.x + b.w / 2;
      const bcy = b.y + b.h / 2;
      const dx = bcx - acx;
      const dy = bcy - acy;
      const dist = Math.hypot(dx, dy) || 1;

      // Gap between AABB faces along the connecting axis.
      const gapX = dx >= 0
        ? b.x - (a.x + a.w)
        : a.x - (b.x + b.w);
      const gapY = dy >= 0
        ? b.y - (a.y + a.h)
        : a.y - (b.y + b.h);
      const faceGap = Math.abs(dx) >= Math.abs(dy) ? gapX : gapY;
      if (faceGap <= gap) continue;

      const pull = Math.min(faceGap - gap, faceGap * strength) * Math.min(1, 0.35 + bonds * 0.15);
      if (pull <= 0.5) continue;
      const ux = dx / dist;
      const uy = dy / dist;
      translate(idA, ux * pull * 0.5, uy * pull * 0.5);
      translate(idB, -ux * pull * 0.5, -uy * pull * 0.5);
      moved = true;
    }
    if (!moved) break;
  }
  return positions;
}

/** Account boxes must never overlap. */
function separateAccountBoxesNeverOverlap(positions, nodes, boundaries, gap = 56, edges = null) {
  return separateBoundaryKindPreferNoOverlap(
    positions, nodes, boundaries, "account", { gap, iterations: 80, edges },
  );
}

/** Sibling VPC boxes should not overlap. */
function separateVpcBoxesPreferNoOverlap(positions, nodes, boundaries, gap = 40, edges = null) {
  return separateBoundaryKindPreferNoOverlap(
    positions, nodes, boundaries, "vpc", { gap, iterations: 64, edges },
  );
}

/** Sibling subnet boxes should not overlap. */
function separateSubnetBoxesPreferNoOverlap(positions, nodes, boundaries, gap = 32, edges = null) {
  return separateBoundaryKindPreferNoOverlap(
    positions, nodes, boundaries, "subnet", { gap, iterations: 64, edges },
  );
}

/**
 * Force layout with boundary boxes as supernodes: contract members into a
 * box node, run force on boxes + unhosted nodes, then pack members inside.
 */
function layoutForceWithBoundaryBoxes(nodes, edges, rootId) {
  const visibleIds = new Set(nodes.map((n) => n.id));
  const drawable = selectDrawableBoundaries(state.boundaries || [], visibleIds);
  const packUnits = collectBoundaryPackUnits(drawable, visibleIds);

  const metaIdOf = new Map();
  const metaNodes = [];
  const boxMetas = [];

  for (const unit of packUnits) {
    const members = unit.members.filter((id) => !metaIdOf.has(id));
    if (!members.length) continue;
    const meta = {
      id: unit.metaId,
      label: "ComputeContext",
      display_name: unit.label,
      _isBox: true,
      _boxId: unit.boxId,
      _memberIds: members,
    };
    metaNodes.push(meta);
    boxMetas.push(meta);
    for (const id of members) metaIdOf.set(id, unit.metaId);
  }

  for (const node of nodes) {
    if (metaIdOf.has(node.id)) continue;
    metaNodes.push({ ...node, _isBox: false });
    metaIdOf.set(node.id, node.id);
  }

  if (!boxMetas.length) {
    return assembleComponentLayouts(nodes, edges, rootId, layoutForceComponent);
  }

  const metaEdges = [];
  const seen = new Set();
  for (const edge of edges) {
    const a = metaIdOf.get(edge.src);
    const b = metaIdOf.get(edge.dst);
    if (!a || !b || a === b) continue;
    const key = a < b ? `${a}|${b}` : `${b}|${a}`;
    if (seen.has(key)) continue;
    seen.add(key);
    metaEdges.push({ src: a, dst: b, rel: edge.rel || "LINK" });
  }

  const metaRoot = (rootId && metaIdOf.get(rootId)) || metaNodes[0]?.id;
  const metaPositions = assembleComponentLayouts(
    metaNodes,
    metaEdges,
    metaRoot,
    layoutForceComponent,
  );

  const positions = {};
  for (const meta of metaNodes) {
    const point = metaPositions[meta.id];
    if (!point) continue;
    if (!meta._isBox) {
      // Keep stray / principal nodes outside the packed box radii.
      let x = point.x;
      let y = point.y;
      for (const box of boxMetas) {
        const bp = metaPositions[box.id];
        if (!bp) continue;
        const foot = estimateNodeFootprint(box);
        const minDist = Math.hypot(foot.width, foot.height) / 2 + 96;
        const dx = x - bp.x;
        const dy = y - bp.y;
        const dist = Math.hypot(dx, dy) || 0.01;
        if (dist >= minDist) continue;
        const scale = minDist / dist;
        x = bp.x + dx * scale;
        y = bp.y + dy * scale;
      }
      positions[meta.id] = { x, y };
      continue;
    }
    packMembersAround(positions, meta._memberIds, nodes, point.x, point.y);
  }

  // Any node somehow missed (shouldn't happen) — park near origin.
  for (const node of nodes) {
    if (!positions[node.id]) positions[node.id] = { x: 0, y: 0 };
  }
  ejectUnhostedFromBoundaryBoxes(positions, nodes, state.boundaries || []);
  return positions;
}

/**
 * Push nodes that are not boundary members outside live box hulls so
 * principals / strays don't sit inside subnet or VPC frames.
 */
function ejectUnhostedFromBoundaryBoxes(positions, nodes, boundaries, pad = 40, edges = null) {
  if (!positions || !nodes?.length || !boundaries?.length) return positions;

  const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
  const drawable = selectDrawableBoundaries(boundaries, visibleIds);
  if (!drawable.length) return positions;

  const hosted = new Set();
  for (const boundary of drawable) {
    for (const id of boundary.leafMemberIds || []) {
      if (visibleIds.has(id)) hosted.add(id);
    }
  }
  const unhosted = [...visibleIds].filter((id) => !hosted.has(id));
  if (!unhosted.length) return positions;

  const nodeById = graphNodeMap(nodes);
  const undirected = edges?.length
    ? buildAdjacency(nodes, edges).undirected
    : null;

  for (let iter = 0; iter < 16; iter += 1) {
    const hulls = computeBoundaryHullsFromPositions(positions, nodes, boundaries);
    if (!hulls.length) break;
    let moved = false;

    for (const id of unhosted) {
      const p = positions[id];
      if (!p) continue;
      const src = nodeById.get(id);
      const foot = estimateNodeFootprint(src?._raw || src || { id });
      const clearance = pad + Math.max(foot.width, foot.height) / 2;

      // Bias eject side toward edge neighbors so principals stay near compute.
      let preferX = null;
      let preferY = null;
      if (undirected) {
        let nx = 0;
        let ny = 0;
        let nCount = 0;
        for (const nbr of undirected.get(id) || []) {
          if (!positions[nbr]) continue;
          nx += positions[nbr].x;
          ny += positions[nbr].y;
          nCount += 1;
        }
        if (nCount) {
          preferX = nx / nCount;
          preferY = ny / nCount;
        }
      }

      for (const rect of hulls) {
        const inside = (
          p.x >= rect.x - pad
          && p.x <= rect.x + rect.w + pad
          && p.y >= rect.y - pad
          && p.y <= rect.y + rect.h + pad
        );
        if (!inside) continue;

        const candidates = [
          { side: "left", x: rect.x - clearance, y: p.y },
          { side: "right", x: rect.x + rect.w + clearance, y: p.y },
          { side: "top", x: p.x, y: rect.y - clearance },
          { side: "bottom", x: p.x, y: rect.y + rect.h + clearance },
        ];
        let best = null;
        for (const c of candidates) {
          const travel = Math.hypot(c.x - p.x, c.y - p.y);
          const nearNbr = (preferX == null)
            ? 0
            : Math.hypot(c.x - preferX, c.y - preferY);
          const score = travel + nearNbr * 0.85;
          if (!best || score < best.score) best = { ...c, score };
        }
        if (best) {
          p.x = best.x;
          p.y = best.y;
          moved = true;
        }
      }
    }
    if (!moved) break;
  }
  return positions;
}

function layoutForce(nodes, edges, rootId) {
  if (state.showBoundaryBoxes && (state.boundaries || []).length) {
    const drawable = selectDrawableBoundaries(
      state.boundaries,
      new Set(nodes.map((n) => n.id)),
    );
    if (drawable.length) {
      return {
        positions: layoutForceWithBoundaryBoxes(nodes, edges, rootId),
        boundaryRects: [],
      };
    }
  }
  return {
    positions: assembleComponentLayouts(nodes, edges, rootId, layoutForceComponent),
    boundaryRects: [],
  };
}

/**
 * Soft nudge: when sibling boxes would overlap heavily, translate whole
 * clusters. Kept for tests / optional packing — drawing uses live hulls.
 */
function buildBoundaryRectsFromPositions(positions, nodes, boundaries) {
  const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
  const drawable = selectDrawableBoundaries(boundaries, visibleIds);
  if (!drawable.length) return [];

  const leafFirst = [...drawable].sort((a, b) => b.depth - a.depth);
  const rectById = new Map();
  const membersOf = new Map();

  for (const b of leafFirst) {
    const members = (b.leafMemberIds || []).filter((id) => visibleIds.has(id));
    if (!members.length) continue;
    membersOf.set(b.id, members);
    const margin = boundaryKindMargin(b.kind);
    const nodeById = graphNodeMap(nodes);
    let x = Infinity;
    let y = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (const id of members) {
      const p = positions[id];
      const meta = nodeById.get(id)?._raw || nodeById.get(id) || { id };
      const foot = estimateNodeFootprint(meta);
      x = Math.min(x, p.x - foot.width / 2);
      y = Math.min(y, p.y - foot.height / 2);
      maxX = Math.max(maxX, p.x + foot.width / 2);
      maxY = Math.max(maxY, p.y + foot.height / 2);
    }
    x -= margin;
    y -= margin;
    let w = (maxX - x) + margin;
    let h = (maxY - y) + margin;

    for (const child of rectById.values()) {
      if (child.parentId !== b.id) continue;
      x = Math.min(x, child.x - 8);
      y = Math.min(y, child.y - 8);
      w = Math.max(w, child.x + child.w + 8 - x);
      h = Math.max(h, child.y + child.h + 8 - y);
    }

    rectById.set(b.id, {
      id: b.id,
      parentId: b.parentId && drawable.some((d) => d.id === b.parentId) ? b.parentId : null,
      kind: b.kind,
      label: b.label,
      x,
      y,
      w: Math.max(64, w),
      h: Math.max(48, h),
    });
  }

  const rects = [...rectById.values()];
  const translateCluster = (rect, dy) => {
    if (!dy) return;
    rect.y += dy;
    for (const id of membersOf.get(rect.id) || []) {
      if (positions[id]) positions[id].y += dy;
    }
    // Move nested child rects with the parent cluster.
    for (const child of rects) {
      if (child.parentId === rect.id) {
        child.y += dy;
      }
    }
  };

  for (let iter = 0; iter < 24; iter += 1) {
    let moved = false;
    for (let i = 0; i < rects.length; i += 1) {
      for (let j = i + 1; j < rects.length; j += 1) {
        const a = rects[i];
        const b = rects[j];
        if (a.parentId === b.id || b.parentId === a.id) continue;
        if (rectIoU(a, b) < 0.02) continue;
        const push = 40;
        if (a.y <= b.y) translateCluster(b, push);
        else translateCluster(a, push);
        moved = true;
      }
    }
    if (!moved) break;
  }

  // Re-fit every rect tightly around its (possibly translated) members.
  return finalizeBoundaryRects(positions, nodes, boundaries, [...rectById.values()]);
}

/** Rebuild/expand rects so every member sits inside its box; parents wrap children. */
function finalizeBoundaryRects(positions, nodes, boundaries, seedRects = []) {
  const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
  const drawable = selectDrawableBoundaries(boundaries || state.boundaries || [], visibleIds);
  if (!drawable.length) return [];

  const bySeed = new Map((seedRects || []).map((r) => [r.id, r]));
  const rectById = new Map();

  const deepestFirst = [...drawable].sort((a, b) => b.depth - a.depth);
  const nodeById = graphNodeMap(nodes);
  for (const b of deepestFirst) {
    const members = (b.leafMemberIds || []).filter((id) => visibleIds.has(id));
    if (!members.length) continue;
    const margin = boundaryKindMargin(b.kind);
    let x = Infinity;
    let y = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (const id of members) {
      const p = positions[id];
      const meta = nodeById.get(id)?._raw || nodeById.get(id) || { id };
      const foot = estimateNodeFootprint(meta);
      x = Math.min(x, p.x - foot.width / 2);
      y = Math.min(y, p.y - foot.height / 2);
      maxX = Math.max(maxX, p.x + foot.width / 2);
      maxY = Math.max(maxY, p.y + foot.height / 2);
    }
    x -= margin;
    y -= margin;
    let w = (maxX - x) + margin;
    let h = (maxY - y) + margin;

    for (const child of rectById.values()) {
      if (child.parentId !== b.id) continue;
      x = Math.min(x, child.x - 8);
      y = Math.min(y, child.y - 8);
      w = Math.max(w, child.x + child.w + 8 - x);
      h = Math.max(h, child.y + child.h + 8 - y);
    }

    // Keep seed x/y bias only if it still contains members; otherwise refit.
    const seed = bySeed.get(b.id);
    if (seed) {
      const containsAll = members.every((id) => {
        const p = positions[id];
        return (
          p.x >= seed.x + 12
          && p.x <= seed.x + seed.w - 12
          && p.y >= seed.y + 10
          && p.y <= seed.y + seed.h - 10
        );
      });
      if (containsAll) {
        x = seed.x;
        y = seed.y;
        w = Math.max(seed.w, w);
        h = Math.max(seed.h, h);
      }
    }

    rectById.set(b.id, {
      id: b.id,
      parentId: b.parentId && drawable.some((d) => d.id === b.parentId) ? b.parentId : null,
      kind: b.kind,
      label: b.label,
      x,
      y,
      w: Math.max(64, w),
      h: Math.max(48, h),
    });
  }

  return [...rectById.values()];
}

function computeLayout(nodes, edges, rootId) {
  const mode = state.layoutMode || "force";
  let result;
  if (mode === "swim") {
    result = layoutSwim(nodes, edges, rootId);
  } else if (mode === "helio") {
    result = layoutHelio(nodes, edges, rootId);
  } else if (mode === "space") {
    result = layoutSpace(nodes, edges, rootId);
  } else if (mode === "hierarchy") {
    result = {
      positions: assembleComponentLayouts(nodes, edges, rootId, layoutHierarchyComponent),
      boundaryRects: [],
    };
  } else if (mode === "sugiyama") {
    result = layoutSugiyama(nodes, edges, rootId);
  } else if (mode === "force") {
    result = layoutForce(nodes, edges, rootId);
  } else {
    // diamond (default fallback)
    result = {
      positions: assembleComponentLayouts(nodes, edges, rootId, (n, e, r) =>
        layoutConnectedComponent(n, e, r, { diamond: true })),
      boundaryRects: [],
    };
  }

  const positions = result.positions || {};
  const modeName = state.layoutMode || "force";
  const boxesOn = state.showBoundaryBoxes && state.boundaries?.length;
  const forceWithBoxes = modeName === "force" && boxesOn;

  if (forceWithBoxes) {
    // Subnet packs as supernodes; VPC-direct placed in a top strip afterward.
    separateOverlappingBoundaryBoxes(positions, nodes, state.boundaries, { strategy: "stack" });
    const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
    const drawable = selectDrawableBoundaries(state.boundaries, visibleIds);
    const packUnits = collectBoundaryPackUnits(drawable, visibleIds)
      .filter((u) => !String(u.metaId).endsWith(":direct"));
    rePackBoundaryUnits(positions, nodes, packUnits);
    enforceMinSpacing(positions, nodes, { iterations: 16 });
    rePackBoundaryUnits(positions, nodes, packUnits);
    // Keep edge neighbors near after packing (esp. unhosted principals).
    pullConnectedNeighbors(positions, nodes, edges, {
      iterations: 8,
      strength: 0.1,
      unhostedStrength: 0.32,
      idealPad: 140,
    });
  } else if (modeName === "space") {
    // Keep the space grid; do not cascade-nudge all subnet hulls apart.
    enforceMinSpacing(positions, nodes);
  } else {
    pullConnectedNeighbors(positions, nodes, edges);
    untangleEdgeCrossings(positions, edges);
    enforceMinSpacing(positions, nodes);
  }

  if (boxesOn) {
    const applyBoxRules = () => {
      // Innermost → outermost; pass edges so bonded boxes separate as neighbors.
      separateSubnetBoxesPreferNoOverlap(positions, nodes, state.boundaries, 32, edges);
      placeVpcDirectComputeAtTop(positions, nodes, state.boundaries);
      separateVpcBoxesPreferNoOverlap(positions, nodes, state.boundaries, 40, edges);
      placeVpcDirectComputeAtTop(positions, nodes, state.boundaries);
      separateAccountBoxesNeverOverlap(positions, nodes, state.boundaries, 56, edges);
      ejectUnhostedFromBoundaryBoxes(positions, nodes, state.boundaries, 40, edges);
    };

    applyBoxRules();
    // Rigid box moves can stretch edges — restore proximity, then re-assert rules.
    pullConnectedNeighbors(positions, nodes, edges, {
      iterations: 10,
      strength: 0.1,
      unhostedStrength: 0.34,
      idealPad: 140,
    });
    attractBoundaryNeighbors(positions, nodes, edges, state.boundaries);
    enforceMinSpacing(positions, nodes, { iterations: 18 });
    applyBoxRules();
    pullConnectedNeighbors(positions, nodes, edges, {
      iterations: 6,
      strength: 0.06,
      unhostedStrength: 0.28,
      idealPad: 150,
    });
    ejectUnhostedFromBoundaryBoxes(positions, nodes, state.boundaries, 40, edges);
  }

  state.boundaryRects = [];
  return positions;
}

/**
 * Keep non-nested boundary hulls from overlapping.
 * - stack: one-shot vertical sibling packing (force + boxes)
 * - nudge: only push pairs that actually overlap (space / other layouts)
 */
function separateOverlappingBoundaryBoxes(positions, nodes, boundaries, opts = {}) {
  const gap = opts.gap ?? 40;
  const strategy = opts.strategy || "nudge";
  if (!positions || !nodes?.length || !boundaries?.length) return positions;

  const visibleIds = new Set(nodes.map((n) => n.id).filter((id) => positions[id]));
  const drawable = selectDrawableBoundaries(boundaries, visibleIds);
  if (drawable.length < 2) return positions;

  const membersOf = new Map(
    drawable.map((b) => [
      b.id,
      (b.leafMemberIds || []).filter((id) => visibleIds.has(id)),
    ]),
  );

  const translateMembers = (boxId, dx, dy) => {
    if (!dx && !dy) return;
    for (const id of membersOf.get(boxId) || []) {
      if (!positions[id]) continue;
      positions[id].x += dx;
      positions[id].y += dy;
    }
  };

  const isNestedPair = (a, b, byId) => {
    let cur = a;
    while (cur?.parentId) {
      if (cur.parentId === b.id) return true;
      cur = byId.get(cur.parentId);
    }
    cur = b;
    while (cur?.parentId) {
      if (cur.parentId === a.id) return true;
      cur = byId.get(cur.parentId);
    }
    return false;
  };

  if (strategy === "stack") {
    const byParent = new Map();
    for (const b of drawable) {
      const key = b.parentId && drawable.some((d) => d.id === b.parentId)
        ? b.parentId
        : "__root__";
      if (!byParent.has(key)) byParent.set(key, []);
      byParent.get(key).push(b.id);
    }

    for (const siblingIds of byParent.values()) {
      if (siblingIds.length < 2) continue;
      const hulls = computeBoundaryHullsFromPositions(positions, nodes, boundaries);
      const hullById = new Map(hulls.map((h) => [h.id, h]));
      const siblings = siblingIds
        .map((id) => hullById.get(id))
        .filter(Boolean)
        .sort((a, b) => (a.y + a.h / 2) - (b.y + b.h / 2) || a.x - b.x);
      if (siblings.length < 2) continue;

      let bottom = -Infinity;
      for (const hull of siblings) {
        if (hull.y >= bottom + gap) {
          bottom = hull.y + hull.h;
          continue;
        }
        const dy = (bottom + gap) - hull.y;
        translateMembers(hull.id, 0, dy);
        bottom = hull.y + dy + hull.h;
      }
    }
    return positions;
  }

  // Nudge: resolve real overlaps only — preserves space-filling / layered structure.
  for (let iter = 0; iter < 32; iter += 1) {
    const hulls = computeBoundaryHullsFromPositions(positions, nodes, boundaries);
    if (hulls.length < 2) break;
    const byId = new Map(hulls.map((r) => [r.id, r]));
    let best = null;

    for (let i = 0; i < hulls.length; i += 1) {
      for (let j = i + 1; j < hulls.length; j += 1) {
        const a = hulls[i];
        const b = hulls[j];
        if (isNestedPair(a, b, byId)) continue;
        const ox = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
        const oy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
        if (ox <= 0 || oy <= 0) continue;
        const score = Math.min(ox, oy);
        if (!best || score > best.score) {
          best = { a, b, ox, oy, score };
        }
      }
    }
    if (!best) break;

    const { a, b, ox, oy } = best;
    const push = (oy <= ox ? oy : ox) + gap;
    if (oy <= ox) {
      if (a.y + a.h / 2 <= b.y + b.h / 2) translateMembers(b.id, 0, push);
      else translateMembers(a.id, 0, push);
    } else if (a.x + a.w / 2 <= b.x + b.w / 2) {
      translateMembers(b.id, push, 0);
    } else {
      translateMembers(a.id, push, 0);
    }
  }

  return positions;
}

/** @deprecated alias — maps to computeLayout for older tests */
function computeLayeredLayout(nodes, edges, rootId) {
  return computeLayout(nodes, edges, rootId);
}

function packBoundaryClusters(positions, nodes, boundaries) {
  // Soft Y cluster only; used by older tests. Prefer swim engine in production.
  if (!boundaries?.length || !positions) return positions;
  const visibleIds = new Set(nodes.map((n) => n.id));
  const ordered = [...boundaries].sort((a, b) => b.depth - a.depth);
  for (const boundary of ordered) {
    const members = (boundary.memberIds || []).filter(
      (id) => visibleIds.has(id) && positions[id],
    );
    if (members.length < 2) continue;
    const ys = members.map((id) => positions[id].y);
    const medianY = ys.slice().sort((a, b) => a - b)[Math.floor(ys.length / 2)];
    const gapY = 130;
    const sorted = [...members].sort((a, b) => positions[a].y - positions[b].y);
    const startY = medianY - ((sorted.length - 1) * gapY) / 2;
    sorted.forEach((id, index) => {
      positions[id].y = startY + index * gapY;
    });
  }
  enforceMinSpacing(positions, nodes);
  return positions;
}

/**
 * Choose which boundaries to draw. Drops empty boxes and redundant subnet
 * wrappers (single-subnet VPCs / single-leaf subnets).
 */
function selectDrawableBoundaries(boundaries, visibleIds) {
  const byId = new Map(boundaries.map((b) => [b.id, b]));
  const childrenOf = new Map();
  for (const b of boundaries) childrenOf.set(b.id, []);
  for (const b of boundaries) {
    if (b.parentId && byId.has(b.parentId)) childrenOf.get(b.parentId).push(b.id);
  }

  const visibleLeaves = (b) => (b.leafMemberIds || []).filter((id) => visibleIds.has(id));
  const skip = new Set();

  for (const b of boundaries) {
    if (!visibleLeaves(b).length) skip.add(b.id);
  }

  for (const b of boundaries) {
    if (skip.has(b.id) || b.kind !== "subnet") continue;
    const parent = b.parentId ? byId.get(b.parentId) : null;
    if (!parent || skip.has(parent.id)) continue;
    if (parent.kind !== "vpc") continue;
    const siblingSubnets = (childrenOf.get(parent.id) || [])
      .map((id) => byId.get(id))
      .filter((c) => c && c.kind === "subnet" && !skip.has(c.id));
    const parentDirect = (parent.memberIds || []).filter((id) => visibleIds.has(id));
    if (siblingSubnets.length <= 1 && parentDirect.length === 0) {
      skip.add(b.id);
      continue;
    }
    if (visibleLeaves(b).length <= 1) skip.add(b.id);
  }

  return boundaries.filter((b) => !skip.has(b.id));
}

/**
 * Axis-aligned hulls that wrap member node glyphs (+ nested child hulls).
 * Uses label footprints plus a thin margin so boxes stay snug.
 */
function boundaryKindMargin(kind) {
  if (kind === "account") return 14;
  if (kind === "vpc") return 10;
  return 8;
}

function computeBoundaryHullsFromPositions(positions, nodes, boundaries) {
  const visibleIds = new Set(
    (nodes || []).map((n) => n.id).filter((id) => positions?.[id]),
  );
  const drawable = selectDrawableBoundaries(boundaries || [], visibleIds);
  if (!drawable.length) return [];

  const nodeById = graphNodeMap(nodes || []);
  const deepestFirst = [...drawable].sort((a, b) => b.depth - a.depth);
  const rectById = new Map();

  for (const boundary of deepestFirst) {
    const memberIds = (boundary.leafMemberIds || []).filter((id) => visibleIds.has(id));
    if (!memberIds.length) continue;

    const margin = boundaryKindMargin(boundary.kind);
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    let any = false;
    for (const id of memberIds) {
      const p = positions[id];
      if (!p) continue;
      const src = nodeById.get(id);
      const meta = src?._raw || src || { id };
      const foot = estimateNodeFootprint(meta);
      any = true;
      minX = Math.min(minX, p.x - foot.width / 2);
      maxX = Math.max(maxX, p.x + foot.width / 2);
      minY = Math.min(minY, p.y - foot.height / 2);
      maxY = Math.max(maxY, p.y + foot.height / 2);
    }
    if (!any) continue;

    minX -= margin;
    maxX += margin;
    minY -= margin;
    maxY += margin;

    const nest = 8;
    for (const child of rectById.values()) {
      if (child.parentId !== boundary.id) continue;
      minX = Math.min(minX, child.x - nest);
      minY = Math.min(minY, child.y - nest);
      maxX = Math.max(maxX, child.x + child.w + nest);
      maxY = Math.max(maxY, child.y + child.h + nest);
    }

    rectById.set(boundary.id, {
      id: boundary.id,
      parentId: boundary.parentId && drawable.some((d) => d.id === boundary.parentId)
        ? boundary.parentId
        : null,
      kind: boundary.kind,
      label: boundary.label,
      x: minX,
      y: minY,
      w: Math.max(64, maxX - minX),
      h: Math.max(48, maxY - minY),
    });
  }

  return [...rectById.values()];
}

function computeLiveBoundaryHulls() {
  if (!state.showBoundaryBoxes || !state.network || !state.boundaries?.length) return [];
  const nodes = state.nodesDS?.get() || [];
  const ids = nodes.map((n) => n.id);
  let positions;
  try {
    positions = state.network.getPositions(ids);
  } catch {
    return [];
  }
  return computeBoundaryHullsFromPositions(positions, nodes, state.boundaries);
}

/** Border hit of center→center segment on a rect (for box↔box peering). */
function rectBorderPointToward(rect, towardX, towardY) {
  const cx = rect.x + rect.w / 2;
  const cy = rect.y + rect.h / 2;
  const dx = towardX - cx;
  const dy = towardY - cy;
  if (!dx && !dy) return { x: cx, y: cy };
  const hx = rect.w / 2;
  const hy = rect.h / 2;
  const sx = dx !== 0 ? hx / Math.abs(dx) : Infinity;
  const sy = dy !== 0 ? hy / Math.abs(dy) : Infinity;
  const t = Math.min(sx, sy);
  return { x: cx + dx * t, y: cy + dy * t };
}

function drawBoundaryBoxes(ctx) {
  if (!state.showBoundaryBoxes) return;
  // Always size boxes from live node positions (drag/layout), not frozen layout rects.
  const hulls = computeLiveBoundaryHulls();
  state.boundaryRects = hulls;
  if (!hulls.length) return;

  const paintOrder = [...hulls].sort((a, b) => {
    const ka = a.kind === "account" ? 0 : a.kind === "vpc" ? 1 : 2;
    const kb = b.kind === "account" ? 0 : b.kind === "vpc" ? 1 : 2;
    if (ka !== kb) return ka - kb;
    return (b.w * b.h) - (a.w * a.h);
  });
  const labelSlots = [];
  const activeId = state.boxDrag?.boundaryId || null;

  for (const rect of paintOrder) {
    const style = BOUNDARY_BOX_STYLES[rect.kind] || BOUNDARY_BOX_STYLES.default;
    const radius = 14;
    const { x, y, w, h } = rect;
    const active = activeId === rect.id;

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + w - radius, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + radius);
    ctx.lineTo(x + w, y + h - radius);
    ctx.quadraticCurveTo(x + w, y + h, x + w - radius, y + h);
    ctx.lineTo(x + radius, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - radius);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.closePath();
    ctx.fillStyle = style.fill;
    ctx.fill();
    ctx.strokeStyle = active ? "#7ee787" : style.stroke;
    ctx.lineWidth = active ? 3.5 : (rect.kind === "account" ? 2.5 : 1.75);
    ctx.setLineDash(rect.kind === "account" && !active ? [8, 5] : []);
    ctx.stroke();
    ctx.setLineDash([]);

    let labelY = y - 4;
    while (labelSlots.some((slot) => (
      Math.abs(slot.x - x) < 48 && Math.abs(slot.y - labelY) < 13
    ))) {
      labelY -= 14;
    }
    labelSlots.push({ x, y: labelY });

    const header = truncateBoundaryLabel(rect.label || rect.kind, 42);
    ctx.font = "bold 12px -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";
    ctx.textBaseline = "bottom";
    const textW = Math.min(ctx.measureText(header).width + 8, w - 8);
    ctx.fillStyle = "rgba(13, 17, 23, 0.72)";
    ctx.fillRect(x + 6, labelY - 12, textW, 14);
    ctx.fillStyle = active ? "#7ee787" : style.label;
    ctx.fillText(header, x + 10, labelY);
    ctx.restore();
  }
}

/** Innermost (smallest-area) boundary rect containing a canvas-space point. */
function findBoundaryBoxAt(rects, x, y) {
  if (!rects?.length) return null;
  const hits = rects.filter((r) => (
    Number.isFinite(r.x)
    && Number.isFinite(r.y)
    && x >= r.x
    && x <= r.x + r.w
    && y >= r.y
    && y <= r.y + r.h
  ));
  if (!hits.length) return null;
  hits.sort((a, b) => {
    const area = (a.w * a.h) - (b.w * b.h);
    if (area !== 0) return area;
    const rank = (k) => (k === "subnet" ? 2 : k === "vpc" ? 1 : 0);
    return rank(b.kind) - rank(a.kind);
  });
  return hits[0];
}

function memberIdsForBoundary(boundaryId) {
  const boundary = (state.boundaries || []).find((b) => b.id === boundaryId);
  if (!boundary) return [];
  const visible = new Set((state.nodesDS?.get() || []).map((n) => n.id));
  return (boundary.leafMemberIds || []).filter((id) => visible.has(id));
}

function pointerToNetworkCanvas(network, event, { allowOutside = false } = {}) {
  if (!network) return null;
  const canvas = network.canvas?.frame?.canvas;
  if (!canvas) return null;
  const rect = canvas.getBoundingClientRect();
  const dom = {
    x: event.clientX - rect.left,
    y: event.clientY - rect.top,
  };
  if (
    !allowOutside
    && (dom.x < -2 || dom.y < -2 || dom.x > rect.width + 2 || dom.y > rect.height + 2)
  ) {
    return null;
  }
  try {
    return network.DOMtoCanvas(dom);
  } catch {
    return null;
  }
}

/** Move every visible member of a boundary by a canvas-space delta. */
function translateBoundaryBoxMembers(network, memberIds, dx, dy) {
  if (!network || !memberIds?.length) return;
  if (!dx && !dy) return;
  let positions;
  try {
    positions = network.getPositions(memberIds);
  } catch {
    return;
  }
  for (const id of memberIds) {
    const p = positions[id];
    if (!p) continue;
    network.moveNode(id, p.x + dx, p.y + dy);
  }
}

/**
 * Drag empty space inside a bounding box to move the box + its member nodes.
 * Node hits still win (drag the node instead).
 */
function wireBoundaryBoxDragging(network) {
  const container = document.getElementById("graph");
  if (!network || !container || container.dataset.boxDragWired === "1") return;
  container.dataset.boxDragWired = "1";

  const endDrag = () => {
    if (!state.boxDrag) return;
    state.boxDrag = null;
    try {
      network.setOptions({ interaction: { dragView: true } });
    } catch {
      /* ignore */
    }
    container.style.cursor = "";
    network.redraw();
  };

  container.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    if (!state.showBoundaryBoxes || state.network !== network) return;
    if (nodeIdAtPointer(network, event)) return;

    const canvasPos = pointerToNetworkCanvas(network, event);
    if (!canvasPos) return;

    const hulls = computeLiveBoundaryHulls();
    state.boundaryRects = hulls;
    const box = findBoundaryBoxAt(hulls, canvasPos.x, canvasPos.y);
    if (!box) return;

    const memberIds = memberIdsForBoundary(box.id);
    if (!memberIds.length) return;

    event.preventDefault();
    event.stopPropagation();

    state.boxDrag = {
      boundaryId: box.id,
      memberIds,
      lastX: canvasPos.x,
      lastY: canvasPos.y,
    };
    try {
      network.setOptions({ interaction: { dragView: false } });
    } catch {
      /* ignore */
    }
    container.style.cursor = "grabbing";
    try {
      container.setPointerCapture(event.pointerId);
    } catch {
      /* ignore */
    }
    network.redraw();
  }, true);

  container.addEventListener("pointermove", (event) => {
    if (state.boxDrag) {
      const canvasPos = pointerToNetworkCanvas(network, event, { allowOutside: true });
      if (!canvasPos) return;
      const dx = canvasPos.x - state.boxDrag.lastX;
      const dy = canvasPos.y - state.boxDrag.lastY;
      if (dx || dy) {
        state.boxDrag.lastX = canvasPos.x;
        state.boxDrag.lastY = canvasPos.y;
        translateBoundaryBoxMembers(network, state.boxDrag.memberIds, dx, dy);
      }
      return;
    }

    if (!state.showBoundaryBoxes) {
      container.style.cursor = "";
      return;
    }
    if (nodeIdAtPointer(network, event)) {
      container.style.cursor = "";
      return;
    }
    const canvasPos = pointerToNetworkCanvas(network, event);
    if (!canvasPos) {
      container.style.cursor = "";
      return;
    }
    const box = findBoundaryBoxAt(state.boundaryRects || [], canvasPos.x, canvasPos.y);
    container.style.cursor = box ? "grab" : "";
  });

  container.addEventListener("pointerup", endDrag);
  container.addEventListener("pointercancel", endDrag);
}

function drawBoxPeeringEdges(ctx) {
  if (!state.showBoundaryBoxes || !state.boxPeeringEdges?.length || !state.boundaryRects?.length) {
    return;
  }
  const rectById = new Map(state.boundaryRects.map((r) => [r.id, r]));

  for (const edge of state.boxPeeringEdges) {
    const a = rectById.get(edge.src);
    const b = rectById.get(edge.dst);
    if (!a || !b) continue;
    const acx = a.x + a.w / 2;
    const acy = a.y + a.h / 2;
    const bcx = b.x + b.w / 2;
    const bcy = b.y + b.h / 2;
    const start = rectBorderPointToward(a, bcx, bcy);
    const end = rectBorderPointToward(b, acx, acy);
    const mx = (start.x + end.x) / 2;
    const my = (start.y + end.y) / 2;

    ctx.save();
    ctx.strokeStyle = "#3fb9b0";
    ctx.lineWidth = 2.25;
    ctx.setLineDash([10, 6]);
    ctx.beginPath();
    ctx.moveTo(start.x, start.y);
    ctx.lineTo(end.x, end.y);
    ctx.stroke();
    ctx.setLineDash([]);

    const angle = Math.atan2(end.y - start.y, end.x - start.x);
    ctx.beginPath();
    ctx.moveTo(end.x, end.y);
    ctx.lineTo(end.x - 12 * Math.cos(angle - 0.35), end.y - 12 * Math.sin(angle - 0.35));
    ctx.lineTo(end.x - 12 * Math.cos(angle + 0.35), end.y - 12 * Math.sin(angle + 0.35));
    ctx.closePath();
    ctx.fillStyle = "#3fb9b0";
    ctx.fill();

    ctx.font = "bold 11px -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";
    ctx.fillStyle = "#56d4dd";
    ctx.textAlign = "center";
    ctx.fillText("VPC_PEERS", mx, my - 6);
    ctx.textAlign = "start";
    ctx.restore();
  }
}

function rectIoU(a, b) {
  const ix = Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x));
  const iy = Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y));
  const inter = ix * iy;
  if (inter <= 0) return 0;
  const union = a.w * a.h + b.w * b.h - inter;
  return union > 0 ? inter / union : 0;
}

function truncateBoundaryLabel(text, maxLen) {
  const s = String(text || "");
  if (s.length <= maxLen) return s;
  return `${s.slice(0, maxLen - 1)}…`;
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

  state.network.on("beforeDrawing", (ctx) => {
    drawBoundaryBoxes(ctx);
  });
  state.network.on("afterDrawing", (ctx) => {
    drawBoxPeeringEdges(ctx);
  });

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

  state.network.on("dragEnd", () => {
    state.network?.redraw();
  });

  wireEdgeInteractionHandlers(state.network, state.edgesDS);
  wireBoundaryBoxDragging(state.network);

  window.addEventListener("resize", () => {
    resizeGraphNetworks();
  });

  initContextMenu();
  initEnrichmentUpload();
  initPathGraph();
  initPanelResizer();
  restoreGraphViewPreference();
  restoreLayoutModePreference();
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
  state.nodePositions = computeLayout(visibleNodes, edges, state.layoutRootId);

  state.nodesDS.update(visibleNodes.map((node) => toVisNode(node, state.nodePositions[node.id])));
  state.network?.redraw();
  if (fit) {
    const focusIds = primaryLayoutFocusIds(visibleNodes, edges, state.layoutRootId);
    fitGraphView({ nodeIds: focusIds });
  }
}

function restoreLayoutModePreference() {
  const stored = localStorage.getItem("samoyed-layout-mode");
  const allowed = new Set(LAYOUT_MODE_IDS);
  if (stored && allowed.has(stored)) {
    state.layoutMode = stored;
  } else {
    state.layoutMode = "force";
  }
  const select = document.getElementById("layoutMode");
  if (select) select.value = state.layoutMode || "force";
}

function setLayoutMode(mode) {
  const allowed = new Set(LAYOUT_MODE_IDS);
  if (!allowed.has(mode)) return;
  state.layoutMode = mode;
  localStorage.setItem("samoyed-layout-mode", mode);
  const select = document.getElementById("layoutMode");
  if (select && select.value !== mode) select.value = mode;
  if (state.graph) renderGraph(state.graph);
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
    if (options.showBoundaryBoxes != null) {
      state.showBoundaryBoxes = Boolean(options.showBoundaryBoxes);
    }
    if (options.layoutMode != null) {
      state.layoutMode = String(options.layoutMode);
    }
    return normalizeGraphForDisplay(graph);
  },
  buildEdges(edges, nodes) {
    return buildVisEdges(edges, graphNodeMap(nodes));
  },
  buildBoundaries(graph) {
    return buildBoundaryModel(graph);
  },
  selectDrawableBoundaries,
  packBoundaryClusters,
  assignLayoutLevels,
  layoutConnectedComponent,
  computeLayout,
  enforceMinSpacing,
  pullConnectedNeighbors,
  untangleEdgeCrossings,
  layoutSwim,
  layoutHelio,
  layoutSpace,
  layoutSugiyama,
  layoutForce,
  layoutForceWithBoundaryBoxes,
  packMembersAround,
  collectBoundaryPackUnits,
  placeVpcDirectComputeAtTop,
  separateAccountBoxesNeverOverlap,
  separateVpcBoxesPreferNoOverlap,
  separateSubnetBoxesPreferNoOverlap,
  attractBoundaryNeighbors,
  ejectUnhostedFromBoundaryBoxes,
  buildBoxPeeringEdges,
  buildBoundaryRectsFromPositions,
  computeBoundaryHullsFromPositions,
  separateOverlappingBoundaryBoxes,
  findBoundaryBoxAt,
  memberIdsForBoundary,
  isBoundaryNode,
  getState: () => ({
    layoutMode: state.layoutMode,
    showBoundaryBoxes: state.showBoundaryBoxes,
    boundaryRects: state.boundaryRects,
    boxPeeringEdges: state.boxPeeringEdges,
    boundaries: state.boundaries,
  }),
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
document.getElementById("toggleBoundaryBoxes")?.addEventListener("change", (event) => {
  state.showBoundaryBoxes = !!event.target.checked;
  // Re-layout: box rects / box peering depend on this toggle.
  if (state.graph) renderGraph(state.graph);
});
document.getElementById("layoutMode")?.addEventListener("change", (event) => {
  setLayoutMode(event.target.value);
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
