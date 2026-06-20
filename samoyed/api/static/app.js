/* Samoyed graph UI */

const state = {
  sessionId: null,
  sessionMeta: null,
  graph: { nodes: [], edges: [] },
  network: null,
  nodesDS: null,
  edgesDS: null,
  selectedNodeId: null,
  highlightedPath: null,
  callerNodeId: null,
};

const NODE_COLORS = {
  Principal: { background: "#1f6feb", border: "#58a6ff", highlight: { background: "#388bfd", border: "#79c0ff" } },
  Resource: { background: "#8b2520", border: "#f85149", highlight: { background: "#b62324", border: "#ff7b72" } },
  ComputeContext: { background: "#1a4d2e", border: "#3fb950", highlight: { background: "#238636", border: "#56d364" } },
  EscapeSurface: { background: "#4a2870", border: "#d2a8ff", highlight: { background: "#6e40b8", border: "#e2b0ff" } },
  ScopeBoundary: { background: "#30363d", border: "#8b949e", highlight: { background: "#484f58", border: "#b1bac4" } },
  PolicyStatement: { background: "#5a3c00", border: "#ffa657", highlight: { background: "#7d4e00", border: "#ffc078" } },
  Unknown: { background: "#21262d", border: "#484f58", highlight: { background: "#30363d", border: "#8b949e" } },
};

const PATH_NODE_COLOR = { background: "#9e6a03", border: "#ffa657" };
const PATH_EDGE_COLOR = { color: "#ffa657", highlight: "#ffc078" };
const SELECTED_NODE_COLOR = { background: "#388bfd", border: "#79c0ff" };

async function fetchJSON(url, opts) {
  const res = await fetch(url, { credentials: "same-origin", ...opts });
  if (res.status === 401) {
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login?next=${next}`;
    throw new Error("Not authenticated");
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
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
  return node.display_name || node.native_id || node.arn || node.name || node.id;
}

function shortId(id) {
  if (!id) return "";
  if (id.length <= 36) return id;
  const parts = id.split(":");
  return parts.length > 2 ? parts.slice(-2).join(":") : id.slice(0, 32) + "…";
}

function nodeColor(label) {
  return NODE_COLORS[label] || NODE_COLORS.Unknown;
}

function toVisNode(node) {
  const label = node.label || "Unknown";
  const colors = nodeColor(label);
  const title = [
    `Label: ${label}`,
    `Concept: ${node.concept_type || "—"}`,
    `ID: ${node.id}`,
    node.native_id ? `Native: ${node.native_id}` : null,
  ].filter(Boolean).join("\n");

  return {
    id: node.id,
    label: shortId(displayName(node)),
    title,
    group: label,
    color: { ...colors },
    font: { color: "#e6edf3", size: 12 },
    shape: label === "Principal" ? "dot" : "box",
    size: label === "Principal" ? 18 : undefined,
    _raw: node,
  };
}

function toVisEdge(edge) {
  return {
    id: `${edge.src}|${edge.rel}|${edge.dst}`,
    from: edge.src,
    to: edge.dst,
    label: edge.rel,
    title: edge.rel,
    arrows: "to",
    font: { align: "middle", size: 9, color: "#8b949e", strokeWidth: 0 },
    color: { color: "#484f58", highlight: "#58a6ff", hover: "#8b949e" },
    smooth: { type: "curvedCW", roundness: 0.15 },
    _raw: edge,
  };
}

function initNetwork() {
  const container = document.getElementById("graph");
  state.nodesDS = new vis.DataSet([]);
  state.edgesDS = new vis.DataSet([]);

  const options = {
    physics: {
      enabled: true,
      solver: "forceAtlas2Based",
      forceAtlas2Based: {
        gravitationalConstant: -38,
        centralGravity: 0.008,
        springLength: 120,
        springConstant: 0.06,
        damping: 0.42,
      },
      stabilization: { iterations: 150 },
    },
    interaction: {
      hover: true,
      tooltipDelay: 120,
      multiselect: false,
    },
    edges: {
      width: 1.5,
      selectionWidth: 2.5,
    },
    nodes: {
      borderWidth: 2,
      margin: 8,
    },
  };

  state.network = new vis.Network(container, { nodes: state.nodesDS, edges: state.edgesDS }, options);

  state.network.on("click", (params) => {
    if (params.nodes.length) {
      selectNode(params.nodes[0]);
    }
  });

  state.network.on("doubleClick", (params) => {
    if (params.nodes.length) {
      state.network.focus(params.nodes[0], { scale: 1.2, animation: true });
    }
  });
}

function renderGraph(graph) {
  state.graph = graph;
  const visibleNodes = graph.nodes.filter((n) => n.label !== "CollectionSession");
  state.nodesDS.clear();
  state.edgesDS.clear();
  state.nodesDS.add(visibleNodes.map(toVisNode));

  const nodeIds = new Set(visibleNodes.map((n) => n.id));
  const edges = graph.edges.filter((e) => nodeIds.has(e.src) && nodeIds.has(e.dst) && e.rel !== "DISCOVERED");
  state.edgesDS.add(edges.map(toVisEdge));

  state.callerNodeId = visibleNodes.find((n) => n.is_caller)?.id || null;
  populateNodeDatalist(visibleNodes);
}

function populateNodeDatalist(nodes) {
  const dl = document.getElementById("nodeOptions");
  dl.innerHTML = '<option value="caller">caller (compromised identity)</option>';
  nodes
    .slice()
    .sort((a, b) => displayName(a).localeCompare(displayName(b)))
    .forEach((n) => {
      const opt = document.createElement("option");
      opt.value = n.id;
      opt.label = `${n.label}: ${displayName(n)}`;
      dl.appendChild(opt);
    });
}

function clearHighlight() {
  state.highlightedPath = null;
  const visibleNodes = state.graph.nodes.filter((n) => n.label !== "CollectionSession");
  state.nodesDS.update(visibleNodes.map(toVisNode));
  const nodeIds = new Set(visibleNodes.map((n) => n.id));
  const edges = state.graph.edges.filter((e) => nodeIds.has(e.src) && nodeIds.has(e.dst) && e.rel !== "DISCOVERED");
  state.edgesDS.update(edges.map(toVisEdge));
}

function highlightPath(path) {
  if (!path) return;
  state.highlightedPath = path;
  const nodeSet = new Set(path.node_ids || []);
  const edgeKeys = new Set();

  (path.steps || []).forEach((s) => {
    edgeKeys.add(`${s.src}|${s.rel}|${s.dst}`);
  });

  state.nodesDS.get().forEach((n) => {
    if (nodeSet.has(n.id)) {
      state.nodesDS.update({ id: n.id, color: PATH_NODE_COLOR, borderWidth: 3 });
    } else {
      state.nodesDS.update({ id: n.id, color: { ...nodeColor(n.group), opacity: 0.35 } });
    }
  });

  state.edgesDS.get().forEach((e) => {
    if (edgeKeys.has(e.id)) {
      state.edgesDS.update({
        id: e.id,
        color: PATH_EDGE_COLOR,
        width: 3,
        font: { size: 11, color: "#ffa657", strokeWidth: 0 },
      });
    } else {
      state.edgesDS.update({
        id: e.id,
        color: { color: "#30363d", highlight: "#484f58" },
        width: 1,
      });
    }
  });

  state.network.fit({
    nodes: [...nodeSet],
    animation: { duration: 500, easingFunction: "easeInOutQuad" },
  });
}

function selectNode(nodeId) {
  state.selectedNodeId = nodeId;
  const visNode = state.nodesDS.get(nodeId);
  const raw = visNode?._raw || state.graph.nodes.find((n) => n.id === nodeId);
  if (!raw) return;

  document.getElementById("nodeHint").style.display = "none";
  document.getElementById("nodeDetail").style.display = "block";
  document.getElementById("nodeTitle").textContent = `${raw.label} — ${displayName(raw)}`;
  const { id, label, ...props } = raw;
  document.getElementById("nodeProps").textContent = JSON.stringify(props, null, 2);

  state.nodesDS.update({ id: nodeId, color: SELECTED_NODE_COLOR, borderWidth: 3 });
  switchTab("node");
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
}

function renderPaths(paths) {
  const ul = document.getElementById("paths");
  document.getElementById("pathCount").textContent = String(paths.length);
  ul.innerHTML = "";

  if (!paths.length) {
    ul.innerHTML = '<li class="empty">No paths found</li>';
    return;
  }

  paths.forEach((p) => {
    const li = document.createElement("li");
    const target = p.target_match?.concept_type || p.target_match?.resource_type || "target";
    const steps = (p.steps || []).map((s) => s.rel).join(" → ");
    li.innerHTML = `
      <div class="title"><span class="score">${p.score ?? "—"}</span> → ${target}</div>
      <div class="path-step">${steps || "direct"}</div>
    `;
    li.onclick = () => highlightPath(p);
    ul.appendChild(li);
  });
}

async function runPathQuery(query) {
  if (!state.sessionId) return alert("Select a session first");
  const body = {
    start: query.start ?? document.getElementById("startSearch").value || "caller",
    target_concept: query.target_concept ?? document.getElementById("targetConcept").value || null,
    target_resource_type: query.target_resource_type ?? document.getElementById("targetResourceType").value || null,
    max_depth: Number(query.max_depth ?? document.getElementById("maxDepth").value || 6),
    mode: query.mode ?? document.getElementById("searchMode").value,
  };
  if (!body.target_concept) delete body.target_concept;
  if (!body.target_resource_type) delete body.target_resource_type;

  const data = await fetchJSON(`/api/sessions/${state.sessionId}/paths/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  renderPaths(data.paths || []);
  if (data.paths?.length) highlightPath(data.paths[0]);
  return data;
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
    renderPaths(data.paths || []);
    if (data.paths?.length) highlightPath(data.paths[0]);
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
  state.sessionId = sessionId;
  const [meta, graph] = await Promise.all([
    fetchJSON(`/api/sessions/${sessionId}`),
    fetchJSON(`/api/sessions/${sessionId}/graph`),
  ]);
  state.sessionMeta = meta;
  document.getElementById("sessionBadge").textContent = `${sessionId} · ${shortId(meta.caller_arn)}`;
  renderGraph(graph);
  clearHighlight();
  renderPaths([]);
  await loadSuggestions();

  document.querySelectorAll("#sessions li").forEach((li) => {
    li.classList.toggle("active", li.dataset.id === sessionId);
  });

  if (state.callerNodeId) {
    setTimeout(() => state.network.focus(state.callerNodeId, { scale: 1.1, animation: true }), 400);
  } else {
    state.network.fit({ animation: true });
  }
}

async function refreshSessions() {
  const sessions = await fetchJSON("/api/sessions");
  const ul = document.getElementById("sessions");
  ul.innerHTML = "";
  sessions.forEach((s) => {
    const li = document.createElement("li");
    li.dataset.id = s.session_id;
    li.innerHTML = `
      <div class="title">${s.session_id}</div>
      <div class="desc">${shortId(s.caller_arn || "")}</div>
    `;
    li.onclick = () => loadSession(s.session_id);
    ul.appendChild(li);
  });
  if (sessions.length && !state.sessionId) {
    await loadSession(sessions[0].session_id);
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
  renderGraph(graph);
  selectNode(state.selectedNodeId);
  document.getElementById("propKey").value = "";
  document.getElementById("propValue").value = "";
}

function updateTargetFieldsVisibility() {
  const mode = document.getElementById("searchMode").value;
  document.getElementById("targetFields").style.display = mode === "paths" ? "block" : "none";
}

// Event wiring
document.getElementById("refreshSessions").onclick = refreshSessions;
document.getElementById("loadAwsSample").onclick = async () => {
  const s = await fetchJSON("/api/sessions/sample", { method: "POST" });
  await refreshSessions();
  await loadSession(s.session_id);
};
document.getElementById("loadK8sSample").onclick = async () => {
  const s = await fetchJSON("/api/sessions/sample-k8s", { method: "POST" });
  await refreshSessions();
  await loadSession(s.session_id);
};
document.getElementById("loadGcpSample").onclick = async () => {
  const s = await fetchJSON("/api/sessions/sample-gcp", { method: "POST" });
  await refreshSessions();
  await loadSession(s.session_id);
};
document.getElementById("loadAzureSample").onclick = async () => {
  const s = await fetchJSON("/api/sessions/sample-azure", { method: "POST" });
  await refreshSessions();
  await loadSession(s.session_id);
};
document.getElementById("runSearch").onclick = () => runPathQuery({});
document.getElementById("fitGraph").onclick = () => state.network.fit({ animation: true });
document.getElementById("clearHighlight").onclick = clearHighlight;
document.getElementById("focusCaller").onclick = () => {
  if (state.callerNodeId) state.network.focus(state.callerNodeId, { scale: 1.2, animation: true });
};
document.getElementById("appendProp").onclick = appendProperty;
document.getElementById("searchMode").onchange = updateTargetFieldsVisibility;

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => switchTab(tab.dataset.tab);
});

initNetwork();
updateTargetFieldsVisibility();
initAuth().then(refreshSessions).catch(() => refreshSessions());
