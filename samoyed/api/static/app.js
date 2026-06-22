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

function nodeMarkingColor(node) {
  const compromised = !!node.is_compromised;
  const highValue = !!node.is_high_value;
  if (compromised && highValue) return BOTH_MARKING_COLOR;
  if (compromised) return COMPROMISED_NODE_COLOR;
  if (highValue) return HIGH_VALUE_NODE_COLOR;
  return nodeColor(node.label || "Unknown");
}

function toVisNode(node, position) {
  const label = node.label || "Unknown";
  const colors = nodeMarkingColor(node);
  const titleParts = [
    `Label: ${label}`,
    `Concept: ${node.concept_type || "—"}`,
    `ID: ${node.id}`,
    node.native_id ? `Native: ${node.native_id}` : null,
  ];
  if (node.is_compromised) titleParts.push("⚠ Marked compromised");
  if (node.is_high_value) titleParts.push("★ Marked high-value");
  const title = titleParts.filter(Boolean).join("\n");

  const visNode = {
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

  if (position) {
    visNode.x = position.x;
    visNode.y = position.y;
  }
  return visNode;
}

function graphNodeMap(nodes) {
  return new Map(nodes.map((n) => [n.id, n]));
}

function formatEdgeHint(edge, nodeById) {
  const src = nodeById.get(edge.src);
  const dst = nodeById.get(edge.dst);
  const srcLabel = src ? `${src.label}: ${displayName(src)}` : edge.src;
  const dstLabel = dst ? `${dst.label}: ${displayName(dst)}` : edge.dst;
  const lines = [edge.rel, `${shortId(srcLabel)} → ${shortId(dstLabel)}`];

  const meta = [];
  if (edge.confidence) meta.push(`confidence: ${edge.confidence}`);
  if (edge.action) meta.push(`action: ${edge.action}`);
  if (edge.source) meta.push(`source: ${edge.source}`);
  if (edge.discovered_via) meta.push(`via: ${edge.discovered_via}`);
  if (edge.cartography_rel) meta.push(`cartography: ${edge.cartography_rel}`);
  if (edge.mitre_technique_ids?.length) {
    meta.push(`MITRE: ${edge.mitre_technique_ids.join(", ")}`);
  }
  if (meta.length) lines.push(meta.join(" · "));

  return lines.join("\n");
}

function computeLayeredLayout(nodes, edges, rootId) {
  const nodeIds = nodes.map((n) => n.id);
  const idSet = new Set(nodeIds);
  const outEdges = new Map();

  edges.forEach((edge) => {
    if (!idSet.has(edge.src) || !idSet.has(edge.dst)) return;
    if (!outEdges.has(edge.src)) outEdges.set(edge.src, []);
    outEdges.get(edge.src).push(edge.dst);
  });

  const levels = new Map();
  const roots = [];
  if (rootId && idSet.has(rootId)) roots.push(rootId);
  nodes.forEach((node) => {
    if (node.is_caller && idSet.has(node.id) && !roots.includes(node.id)) roots.push(node.id);
  });
  if (!roots.length && nodeIds.length) roots.push(nodeIds[0]);

  const queue = [...roots];
  roots.forEach((id) => levels.set(id, 0));

  while (queue.length) {
    const id = queue.shift();
    const level = levels.get(id) ?? 0;
    for (const dst of outEdges.get(id) || []) {
      const nextLevel = level + 1;
      if (!levels.has(dst) || levels.get(dst) > nextLevel) {
        levels.set(dst, nextLevel);
        queue.push(dst);
      }
    }
  }

  let fallbackLevel = levels.size ? Math.max(...levels.values()) + 1 : 0;
  nodeIds.forEach((id) => {
    if (!levels.has(id)) {
      levels.set(id, fallbackLevel);
      fallbackLevel += 1;
    }
  });

  const byLevel = new Map();
  levels.forEach((level, id) => {
    if (!byLevel.has(level)) byLevel.set(level, []);
    byLevel.get(level).push(id);
  });

  const xGap = 260;
  const yGap = 120;
  const positions = {};
  [...byLevel.entries()]
    .sort(([a], [b]) => a - b)
    .forEach(([level, ids]) => {
      ids.sort();
      const offset = ((ids.length - 1) * yGap) / 2;
      ids.forEach((id, index) => {
        positions[id] = { x: level * xGap, y: index * yGap - offset };
      });
    });

  return positions;
}

function visEdgeId(edge, idCounts) {
  let base = `${edge.src}|${edge.rel}|${edge.dst}`;
  if (edge.pattern_id) base += `|${edge.pattern_id}`;
  else if (edge.action) base += `|${edge.action}`;
  const seen = idCounts.get(base) || 0;
  idCounts.set(base, seen + 1);
  return seen === 0 ? base : `${base}#${seen}`;
}

function edgeMatchesStep(visEdge, step) {
  const src = step.src || step.src_id;
  const dst = step.dst || step.dst_id;
  const rel = step.rel || step.rel_type;
  return visEdge.from === src && visEdge.to === dst && (visEdge._relLabel === rel || visEdge.label === rel);
}

function buildVisEdges(edges, nodeById) {
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

    const hideLabel = pairTotal > 1;
    const visEdge = {
      id: visEdgeId(edge, idCounts),
      from: edge.src,
      to: edge.dst,
      label: hideLabel ? "" : edge.rel,
      title: hint,
      arrows: "to",
      font: { align: "horizontal", size: 9, color: "#8b949e", strokeWidth: 0 },
      color: { color: "#484f58", highlight: "#58a6ff", hover: "#8b949e" },
      smooth,
      _raw: edge,
      _hint: hint,
      _relLabel: edge.rel,
      _hideLabel: hideLabel,
    };

    if (edge.src === edge.dst) {
      visEdge.selfReference = {
        size: 24,
        angle: 270,
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

  state.network.on("oncontext", (params) => {
    params.event.preventDefault();
    hideContextMenu();
    if (params.nodes.length) {
      showContextMenu(params.event, params.nodes[0]);
    }
  });

  state.network.on("doubleClick", (params) => {
    if (params.nodes.length) {
      openNodeDetail(params.nodes[0]);
    }
  });

  state.network.on("hoverEdge", (params) => {
    if (!params.edge) return;
    const visEdge = state.edgesDS.get(params.edge);
    if (visEdge?._hideLabel) {
      state.edgesDS.update({ id: params.edge, label: visEdge._relLabel });
    }
    showEdgeTooltip(params.event, visEdge?._hint || visEdge?.title);
  });

  state.network.on("blurEdge", (params) => {
    hideEdgeTooltip();
    if (!params.edge) return;
    const visEdge = state.edgesDS.get(params.edge);
    if (visEdge?._hideLabel) {
      state.edgesDS.update({ id: params.edge, label: "" });
    }
  });
  state.network.on("dragStart", hideEdgeTooltip);
  state.network.on("zoom", hideEdgeTooltip);

  window.addEventListener("resize", () => {
    if (state.network) state.network.redraw();
  });

  initContextMenu();
  initPathGraph();
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
}

function fitGraphView() {
  if (!state.network || !state.nodesDS.get().length) return;
  state.network.fit({ animation: { duration: 350, easingFunction: "easeInOutQuad" } });
}

function applyGraphLayout(visibleNodes, edges, { fit = false } = {}) {
  state.callerNodeId = findScenarioStartNode(visibleNodes);
  state.layoutRootId = state.callerNodeId || visibleNodes[0]?.id || null;
  state.nodePositions = computeLayeredLayout(visibleNodes, edges, state.layoutRootId);

  state.nodesDS.update(visibleNodes.map((node) => toVisNode(node, state.nodePositions[node.id])));
  if (fit) fitGraphView();
}

function renderGraph(graph) {
  state.graph = graph;
  const visibleNodes = graph.nodes.filter((n) => n.label !== "CollectionSession");
  state.nodesDS.clear();
  state.edgesDS.clear();

  const nodeIds = new Set(visibleNodes.map((n) => n.id));
  const nodeById = graphNodeMap(visibleNodes);
  const edges = annotateEdgeSourceIndex(
    graph.edges.filter((e) => nodeIds.has(e.src) && nodeIds.has(e.dst) && e.rel !== "DISCOVERED"),
  );

  state.nodesDS.add(visibleNodes.map((node) => toVisNode(node)));
  state.edgesDS.add(buildVisEdges(edges, nodeById));
  applyGraphLayout(visibleNodes, edges);

  populateNodeDatalist(visibleNodes);
  requestAnimationFrame(fitGraphView);
}

/** Merge server graph into UI without resetting layout (after markings / propagation). */
function syncGraphFromServer(graph) {
  state.graph = graph;
  const visibleNodes = graph.nodes.filter((n) => n.label !== "CollectionSession");
  const nodeIds = new Set(visibleNodes.map((n) => n.id));
  const nodeById = graphNodeMap(visibleNodes);
  const edges = annotateEdgeSourceIndex(
    graph.edges.filter((e) => nodeIds.has(e.src) && nodeIds.has(e.dst) && e.rel !== "DISCOVERED"),
  );

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
  state.edgesDS.add(buildVisEdges(edges, nodeById));
  populateNodeDatalist(visibleNodes);

  if (state.selectedNodeId && nodeIds.has(state.selectedNodeId)) {
    refreshMainGraphSelection();
  }
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

function collectPathSubgraph(paths) {
  const nodeIds = new Set();
  const steps = [];
  const stepKeys = new Set();
  for (const p of paths || []) {
    for (const id of p.node_ids || []) nodeIds.add(id);
    for (const s of p.steps || []) {
      const key = `${s.src}|${s.rel}|${s.dst}`;
      if (stepKeys.has(key)) continue;
      stepKeys.add(key);
      steps.push(s);
    }
  }
  return { nodeIds, steps };
}

function stepsToGraphEdges(steps) {
  return steps.map((step, index) => ({
    src: step.src,
    dst: step.dst,
    rel: step.rel,
    _sourceIndex: index,
  }));
}

function buildHighlightedPathEdges(steps, nodeById) {
  return buildVisEdges(annotateEdgeSourceIndex(stepsToGraphEdges(steps)), nodeById).map((edge) => ({
    ...edge,
    label: edge._relLabel || edge.label,
    _hideLabel: false,
    color: PATH_EDGE_COLOR,
    width: 2.5,
    font: { size: 10, color: "#ffa657", strokeWidth: 0, align: "horizontal" },
  }));
}

function clearGeneratedPathGraph() {
  state.generatedPaths = null;
  const section = document.getElementById("pathGraphSection");
  if (section) section.style.display = "none";
  if (state.pathNodesDS) state.pathNodesDS.clear();
  if (state.pathEdgesDS) state.pathEdgesDS.clear();
}

function renderGeneratedPathGraph(paths, { fit = true } = {}) {
  if (!state.pathNodesDS || !state.pathEdgesDS || !paths?.length) {
    clearGeneratedPathGraph();
    return;
  }

  const { nodeIds, steps } = collectPathSubgraph(paths);
  const visibleNodes = state.graph.nodes.filter((n) => nodeIds.has(n.id));
  if (!visibleNodes.length) {
    clearGeneratedPathGraph();
    return;
  }

  const rootId = paths[0]?.node_ids?.[0] || visibleNodes[0].id;
  const nodeById = graphNodeMap(visibleNodes);
  const layoutEdges = stepsToGraphEdges(steps);
  const positions = computeLayeredLayout(visibleNodes, layoutEdges, rootId);

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
  state.pathEdgesDS.add(buildHighlightedPathEdges(steps, nodeById));

  const badge = document.getElementById("pathGraphBadge");
  if (badge) badge.textContent = `${visibleNodes.length} nodes · ${paths.length} path${paths.length === 1 ? "" : "s"}`;

  if (fit && state.pathNetwork) {
    requestAnimationFrame(() => {
      state.pathNetwork.fit({ animation: { duration: 400, easingFunction: "easeInOutQuad" } });
    });
  }
}

function showGeneratedPaths(paths) {
  state.generatedPaths = paths || [];
  const section = document.getElementById("pathGraphSection");
  if (!paths?.length) {
    if (section) section.style.display = "none";
    clearGeneratedPathGraph();
    return;
  }
  if (section) section.style.display = "block";
  renderGeneratedPathGraph(paths, { fit: true });
}

function refreshMainGraphSelection() {
  if (!state.selectedNodeId) return;
  state.nodesDS.get().forEach((n) => {
    const raw = n._raw;
    if (n.id === state.selectedNodeId) {
      state.nodesDS.update({ id: n.id, color: SELECTED_NODE_COLOR, borderWidth: 3 });
    } else {
      const colors = raw ? nodeMarkingColor(raw) : nodeColor(n.group);
      state.nodesDS.update({ id: n.id, color: { ...colors }, borderWidth: 2 });
    }
  });
}

function setPathSearchStart(nodeId) {
  state.selectedNodeId = nodeId;
  document.getElementById("startSearch").value = nodeId;
  const queryStart = document.getElementById("queryStart");
  if (queryStart) queryStart.value = nodeId;
  refreshMainGraphSelection();
}

function clearHighlight() {
  state.selectedNodeId = null;
  const visibleNodes = state.graph.nodes.filter((n) => n.label !== "CollectionSession");
  state.nodesDS.update(visibleNodes.map((node) => toVisNode(node, state.nodePositions[node.id])));
  const nodeIds = new Set(visibleNodes.map((n) => n.id));
  const nodeById = graphNodeMap(visibleNodes);
  const edges = annotateEdgeSourceIndex(
    state.graph.edges.filter((e) => nodeIds.has(e.src) && nodeIds.has(e.dst) && e.rel !== "DISCOVERED"),
  );
  state.edgesDS.update(buildVisEdges(edges, nodeById));
  clearGeneratedPathGraph();
}

function openNodeDetail(nodeId) {
  state.selectedNodeId = nodeId;
  const visNode = state.nodesDS.get(nodeId);
  const raw = visNode?._raw || state.graph.nodes.find((n) => n.id === nodeId);
  if (!raw) return;

  document.getElementById("nodeHint").style.display = "none";
  document.getElementById("nodeDetail").style.display = "block";
  document.getElementById("nodeTitle").textContent = `${raw.label} — ${displayName(raw)}`;
  const { id, label, ...props } = raw;
  document.getElementById("nodeProps").textContent = JSON.stringify(props, null, 2);

  refreshMainGraphSelection();
  switchTab("node");
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
        ? "No blast-radius paths found — the start node may have no outgoing edges in this session."
        : mode === "neighbors"
          ? "No neighbors found for this node."
          : "No paths found for this query.";
    ul.innerHTML = `<li class="empty">${hint}</li>`;
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
    return state.callerNodeId || "caller";
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

    const data = await fetchJSON(`/api/sessions/${state.sessionId}/paths/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (data.start && data.start !== body.start && body.start !== "caller") {
      document.getElementById("startSearch").value = data.start;
    }

    renderPaths(data.paths || [], mode);
    showGeneratedPaths(data.paths || []);
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
    showGeneratedPaths(data.paths || []);
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
    const [meta, graph] = await Promise.all([
      fetchJSON(`/api/sessions/${sessionId}`),
      fetchJSON(`/api/sessions/${sessionId}/graph`),
    ]);
    state.sessionMeta = meta;
    document.getElementById("sessionBadge").textContent = `${sessionDisplayName(meta)} · ${shortId(meta.caller_arn)}`;
    renderGraph(graph);
    clearHighlight();
    renderPaths([]);
    await Promise.all([loadSuggestions(), refreshMarkingsUI()]);

    document.getElementById("searchMode").value = "blast";
    document.querySelectorAll("#sessions li").forEach((li) => {
      li.classList.toggle("active", li.dataset.id === sessionId);
    });

    await runPathQuery({ mode: "blast" });
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

    const data = await fetchJSON(`/api/sessions/${state.sessionId}/graph/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (data.start) document.getElementById("queryStart").value = data.start;
    const paths = data.paths || [];
    renderPaths(paths, body.mode, { listId: "queryPaths", countId: "queryPathCount" });
    showGeneratedPaths(paths);
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
  if (!state.sessionId || !state.selectedNodeId) return alert("Select a node first");
  return markNode(state.selectedNodeId, { compromised, high_value, clear });
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
    const data = await fetchJSON(`/api/sessions/${state.sessionId}/paths/markings-query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, max_depth: maxDepth, max_paths: 30 }),
    });
    state.markings = data.markings || state.markings;
    refreshMarkingsSummaryFromData(data.markings);
    renderPaths(data.paths || [], kind === "blast_compromised" ? "blast" : "paths");
    showGeneratedPaths(data.paths || []);
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
  if (parts.length) {
    el.innerHTML = parts.join("") + '<div style="margin-top:6px;font-size:11px;color:var(--muted)">Right-click nodes to add or change markings</div>';
  }
}

let contextMenuEl = null;

function initContextMenu() {
  contextMenuEl = document.createElement("div");
  contextMenuEl.id = "graphContextMenu";
  contextMenuEl.className = "context-menu";
  document.body.appendChild(contextMenuEl);
  document.addEventListener("click", hideContextMenu);
  document.addEventListener("scroll", hideContextMenu, true);
}

function hideContextMenu() {
  if (contextMenuEl) contextMenuEl.style.display = "none";
  state.contextMenuNodeId = null;
}

function showContextMenu(event, nodeId) {
  if (!contextMenuEl) return;
  state.contextMenuNodeId = nodeId;
  const raw = state.graph.nodes.find((n) => n.id === nodeId);
  const name = raw ? displayName(raw) : shortId(nodeId);
  const isCompromised = !!raw?.is_compromised;
  const isHighValue = !!raw?.is_high_value;

  contextMenuEl.innerHTML = `
    <div class="context-menu-header">${shortId(name)}</div>
    <button type="button" data-action="mark-compromised">Mark compromised</button>
    <button type="button" data-action="mark-high-value" class="warn">Mark high-value</button>
    <button type="button" data-action="clear-markings">Clear markings</button>
    <hr />
    <button type="button" data-action="blast-from-here">Blast radius from here</button>
    <button type="button" data-action="paths-from-here">Paths from here → secrets</button>
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
  contextMenuEl.querySelector('[data-action="query-compromised-hv"]').onclick = () => {
    hideContextMenu();
    runMarkingPathsQuery("compromised_to_high_value");
  };

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
document.getElementById("importReport").onclick = importReport;
document.getElementById("fitGraph").onclick = fitGraphView;
document.getElementById("relayoutGraph").onclick = () => {
  const visibleNodes = state.graph.nodes.filter((n) => n.label !== "CollectionSession");
  const nodeIds = new Set(visibleNodes.map((n) => n.id));
  const edges = annotateEdgeSourceIndex(
    state.graph.edges.filter((e) => nodeIds.has(e.src) && nodeIds.has(e.dst) && e.rel !== "DISCOVERED"),
  );
  applyGraphLayout(visibleNodes, edges, { fit: true });
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
  .then(() => Promise.all([loadConnectors(), loadFixturesCatalog(), refreshSessions({ scope: "recent", limit: 1, autoLoad: true })]))
  .catch(() => Promise.all([loadConnectors(), loadFixturesCatalog(), refreshSessions({ scope: "recent", limit: 1, autoLoad: true })]));
