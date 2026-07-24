from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


def test_privesc_self_loops_are_never_rendered() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for frontend graph contract test")

    app_js = Path(__file__).parents[1] / "samoyed" / "api" / "static" / "app.js"
    script = f"""
require({json.dumps(str(app_js))});
const display = globalThis.SamoyedGraphDisplay;
const graph = {{
  nodes: [
    {{ id: "principal", label: "Principal" }},
    {{ id: "outcome", label: "AttackOutcome", concept_type: "AttackOutcome" }},
    {{ id: "kms", label: "Resource", native_id: "KMSKey:*" }},
    {{ id: "crown", label: "Resource", native_id: "S3Bucket:crown", high_value: true }},
    {{ id: "role", label: "Principal", concept_type: "Identity" }},
  ],
  edges: [
    {{
      src: "principal", rel: "CAN_PRIVESC_TO", dst: "outcome",
      attack_outcome: "administrator-access", pattern_id: "legacy-outcome",
    }},
    {{
      src: "principal", rel: "CAN_PRIVESC_TO", dst: "principal",
      attack_outcome: "administrator-access", pattern_id: "direct-outcome",
    }},
    {{
      src: "principal", rel: "CAN_PRIVESC_TO", dst: "role",
      pattern_id: "passrole-to-role",
    }},
    {{ src: "principal", rel: "READS", dst: "kms" }},
    {{ src: "principal", rel: "READS", dst: "crown" }},
  ],
}};

const compact = display.normalize(graph, {{ showAllResourceAccess: false }});
const privesc = compact.edges.filter((edge) => edge.rel === "CAN_PRIVESC_TO");
const loops = privesc.filter((edge) => edge.src === edge.dst);
if (loops.length !== 0) {{
  throw new Error(`expected 0 privesc self-loops, got ${{loops.length}}`);
}}
// Outcome-targeted edges are dropped (AttackOutcome nodes are hidden).
if (privesc.some((edge) => edge.dst === "outcome" || edge._collapsedOutcome)) {{
  throw new Error("outcome privesc edges must not render");
}}
// Real principal→role privesc still renders.
if (!privesc.some((edge) => edge.dst === "role")) {{
  throw new Error("passrole privesc to another principal missing");
}}
if (compact.nodes.some((node) => node.id === "kms")) throw new Error("leaf KMS resource rendered");
if (!compact.nodes.some((node) => node.id === "crown")) throw new Error("high-value leaf hidden");
if (compact.nodes.some((node) => node.id === "outcome")) {{
  throw new Error("AttackOutcome node must stay hidden");
}}

const visEdges = display.buildEdges(compact.edges, compact.nodes);
if (visEdges.some((edge) => edge.from === edge.to)) {{
  throw new Error("vis self-loops must not render");
}}
if (visEdges.some((edge) => edge.selfReference)) {{
  throw new Error("selfReference must not be set");
}}

const expanded = display.normalize(graph, {{ showAllResourceAccess: true }});
if (!expanded.nodes.some((node) => node.id === "kms")) throw new Error("resource toggle failed");
"""
    subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)


def test_boundary_nodes_and_hosted_in_are_hidden_from_display() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for frontend graph contract test")

    app_js = Path(__file__).parents[1] / "samoyed" / "api" / "static" / "app.js"
    script = f"""
require({json.dumps(str(app_js))});
const display = globalThis.SamoyedGraphDisplay;
const graph = {{
  nodes: [
    {{ id: "alice", label: "Principal", concept_type: "Identity", display_name: "alice" }},
    {{ id: "web", label: "ComputeContext", concept_type: "RuntimeBinding",
       native_id: "EC2Instance:i-web", vpc_id: "vpc-dmz", account_id: "111111111111" }},
    {{ id: "db", label: "ComputeContext", concept_type: "RuntimeBinding",
       native_id: "EC2Instance:i-db", vpc_id: "vpc-dmz", account_id: "111111111111" }},
    {{ id: "vpc", label: "NetworkBoundary", concept_type: "NetworkBoundary",
       native_id: "aws:vpc:vpc-dmz", boundary_kind: "vpc", display_name: "VPC vpc-dmz",
       account_id: "111111111111" }},
    {{ id: "subnet", label: "NetworkBoundary", concept_type: "NetworkBoundary",
       native_id: "aws:subnet:subnet-a", boundary_kind: "subnet", display_name: "Subnet subnet-a",
       account_id: "111111111111" }},
    {{ id: "account", label: "ScopeBoundary", concept_type: "ScopeBoundary",
       native_id: "aws:account:111111111111", boundary_kind: "account",
       account_id: "111111111111", display_name: "AWS Account 111111111111" }},
    {{ id: "dmz", label: "ScopeBoundary", concept_type: "ScopeBoundary",
       native_id: "aws:scope:dmz", boundary_kind: "environment", environment: "dmz",
       display_name: "DMZ" }},
  ],
  edges: [
    {{ src: "alice", rel: "CAN_ASSUME_ROLE", dst: "web" }},
    {{ src: "web", rel: "HOSTED_IN", dst: "subnet" }},
    {{ src: "db", rel: "HOSTED_IN", dst: "subnet" }},
    {{ src: "subnet", rel: "HOSTED_IN", dst: "vpc" }},
    {{ src: "vpc", rel: "HOSTED_IN", dst: "account" }},
    {{ src: "web", rel: "HOSTED_IN", dst: "dmz" }},
  ],
}};

const displayGraph = display.normalize(graph, {{ showAllResourceAccess: true }});
if (displayGraph.nodes.some((n) => display.isBoundaryNode(n))) {{
  throw new Error("boundary nodes must not be drawn");
}}
if (displayGraph.edges.some((e) => e.rel === "HOSTED_IN")) {{
  throw new Error("HOSTED_IN edges must not be drawn");
}}
if (!displayGraph.nodes.some((n) => n.id === "alice")) {{
  throw new Error("principal should remain visible outside boxes");
}}
if (!displayGraph.nodes.some((n) => n.id === "web")) {{
  throw new Error("compute member should remain visible");
}}

const boundaries = displayGraph.boundaries || display.buildBoundaries(graph);
if (!boundaries.some((b) => b.id === "vpc" && b.kind === "vpc")) {{
  throw new Error("vpc boundary model missing");
}}
if (!boundaries.some((b) => b.id === "subnet" && b.kind === "subnet")) {{
  throw new Error("subnet boundary model missing");
}}
if (!boundaries.some((b) => b.id === "dmz" && b.kind === "environment")) {{
  throw new Error("environment boundary model missing");
}}
// Single-account graph: account box must be gated off.
if (boundaries.some((b) => b.id === "account" || b.kind === "account")) {{
  throw new Error("account boundary must be hidden without cross-account access");
}}

const subnet = boundaries.find((b) => b.id === "subnet");
if (!subnet.leafMemberIds.includes("web") || !subnet.leafMemberIds.includes("db")) {{
  throw new Error("subnet leaf members incomplete");
}}
if (subnet.parentId !== "vpc") {{
  throw new Error(`subnet parent should be vpc, got ${{subnet.parentId}}`);
}}
"""
    subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)


def test_drawable_boundaries_collapse_singleton_subnets() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for frontend graph contract test")

    app_js = Path(__file__).parents[1] / "samoyed" / "api" / "static" / "app.js"
    script = f"""
require({json.dumps(str(app_js))});
const display = globalThis.SamoyedGraphDisplay;
const boundaries = [
  {{
    id: "acct", kind: "account", label: "Account", parentId: null, depth: 0,
    memberIds: [], leafMemberIds: ["a", "b"],
  }},
  {{
    id: "vpc", kind: "vpc", label: "VPC", parentId: "acct", depth: 1,
    memberIds: [], leafMemberIds: ["a", "b"],
  }},
  {{
    id: "subnet", kind: "subnet", label: "Subnet", parentId: "vpc", depth: 2,
    memberIds: ["a", "b"], leafMemberIds: ["a", "b"],
  }},
];
const visible = new Set(["a", "b"]);
const drawn = display.selectDrawableBoundaries(boundaries, visible);
const ids = drawn.map((b) => b.id);
if (!ids.includes("acct") || !ids.includes("vpc")) {{
  throw new Error(`expected account+vpc, got ${{ids}}`);
}}
if (ids.includes("subnet")) {{
  throw new Error("singleton subnet under VPC must be collapsed");
}}

// Soft nudge keeps X ranks and clusters same-boundary members in Y.
const nodes = [
  {{ id: "a", label: "ComputeContext" }},
  {{ id: "b", label: "ComputeContext" }},
  {{ id: "c", label: "ComputeContext" }},
];
const multi = [
  {{
    id: "vpc1", kind: "vpc", label: "VPC-1", parentId: null, depth: 0,
    memberIds: ["a", "b"], leafMemberIds: ["a", "b"],
  }},
];
const seed = {{
  a: {{ x: 100, y: -200 }},
  b: {{ x: 140, y: 220 }},
  c: {{ x: 400, y: 0 }},
}};
const packed = display.packBoundaryClusters(
  {{ a: {{ x: 100, y: -200 }}, b: {{ x: 140, y: 220 }}, c: {{ x: 400, y: 0 }} }},
  nodes,
  multi,
);
if (Math.abs(packed.a.y - packed.b.y) > 140) {{
  throw new Error(`boundary members should cluster in Y: a=${{packed.a.y}} b=${{packed.b.y}}`);
}}
if (Math.abs(packed.c.x - 400) > 1) {{
  throw new Error("unrelated node X must stay put");
}}
"""
    subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)


def test_attack_path_layout_start_left_high_value_right() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for frontend graph contract test")

    app_js = Path(__file__).parents[1] / "samoyed" / "api" / "static" / "app.js"
    script = f"""
require({json.dumps(str(app_js))});
const display = globalThis.SamoyedGraphDisplay;
const nodes = [
  {{ id: "caller", label: "Principal", concept_type: "Identity", is_caller: true }},
  {{ id: "role", label: "Principal", concept_type: "Identity" }},
  {{ id: "compute", label: "ComputeContext", concept_type: "RuntimeBinding" }},
  {{ id: "secret", label: "Resource", concept_type: "SecretStore", is_high_value: true }},
];
const edges = [
  {{ src: "caller", rel: "CAN_ASSUME_ROLE", dst: "role" }},
  {{ src: "role", rel: "EXECUTES", dst: "compute" }},
  {{ src: "compute", rel: "READS", dst: "secret" }},
];
const {{ levels }} = display.assignLayoutLevels(nodes, edges, "caller");
if (levels.get("caller") !== 0) throw new Error("caller must be leftmost rank");
const maxLevel = Math.max(...levels.values());
if (levels.get("secret") !== maxLevel) throw new Error("high-value must be rightmost rank");
if (!(levels.get("role") < levels.get("secret"))) {{
  throw new Error("intermediate should sit left of high-value");
}}
const layout = display.layoutConnectedComponent(nodes, edges, "caller");
if (!(layout.positions.caller.x < layout.positions.secret.x)) {{
  throw new Error("caller X must be left of high-value X");
}}
"""
    subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)


def test_account_boundary_shown_when_cross_account_peering() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for frontend graph contract test")

    app_js = Path(__file__).parents[1] / "samoyed" / "api" / "static" / "app.js"
    script = f"""
require({json.dumps(str(app_js))});
const display = globalThis.SamoyedGraphDisplay;
const graph = {{
  nodes: [
    {{ id: "web", label: "ComputeContext", concept_type: "RuntimeBinding",
       native_id: "EC2Instance:i-dev", account_id: "111111111111" }},
    {{ id: "prod", label: "ComputeContext", concept_type: "RuntimeBinding",
       native_id: "EC2Instance:i-prod", account_id: "222222222222" }},
    {{ id: "acctA", label: "ScopeBoundary", concept_type: "ScopeBoundary",
       native_id: "aws:account:111111111111", boundary_kind: "account", account_id: "111111111111" }},
    {{ id: "acctB", label: "ScopeBoundary", concept_type: "ScopeBoundary",
       native_id: "aws:account:222222222222", boundary_kind: "account",
       account_id: "222222222222", is_cross_account_boundary: true }},
    {{ id: "vpcA", label: "NetworkBoundary", concept_type: "NetworkBoundary",
       native_id: "aws:vpc:vpc-dev", boundary_kind: "vpc", account_id: "111111111111" }},
    {{ id: "vpcB", label: "NetworkBoundary", concept_type: "NetworkBoundary",
       native_id: "aws:vpc:vpc-prod", boundary_kind: "vpc", account_id: "222222222222" }},
  ],
  edges: [
    {{ src: "web", rel: "HOSTED_IN", dst: "vpcA" }},
    {{ src: "vpcA", rel: "HOSTED_IN", dst: "acctA" }},
    {{ src: "prod", rel: "HOSTED_IN", dst: "vpcB" }},
    {{ src: "vpcB", rel: "HOSTED_IN", dst: "acctB" }},
    {{ src: "web", rel: "VPC_PEERS", dst: "acctB", source: "network-enrichment" }},
    {{ src: "acctB", rel: "BRIDGES_TO", dst: "prod", source: "network-enrichment",
       boundary_crossing: true }},
  ],
}};

const boundaries = display.buildBoundaries(graph);
if (!boundaries.some((b) => b.id === "acctA" || b.id === "acctB")) {{
  throw new Error("cross-account access should surface account boxes");
}}

const withBoxes = display.normalize(graph, {{
  showAllResourceAccess: true,
  showBoundaryBoxes: true,
}});
if (withBoxes.nodes.some((n) => n.id === "acctB")) {{
  throw new Error("account boundary glyph must stay hidden even when boxed");
}}
// Boxes on: node-level peering suppressed; box↔box peering recorded.
if (withBoxes.edges.some((e) => e.rel === "VPC_PEERS" || e.rel === "BRIDGES_TO")) {{
  throw new Error("node-level peering must be hidden when boundary boxes are on");
}}
if (!(withBoxes.boxPeeringEdges || []).length) {{
  throw new Error("expected boxPeeringEdges when boxes are on");
}}

const noBoxes = display.normalize(graph, {{
  showAllResourceAccess: true,
  showBoundaryBoxes: false,
}});
const peer = noBoxes.edges.find(
  (e) => e.src === "web" && e.dst === "prod" && e.rel === "VPC_PEERS",
);
if (!peer) {{
  throw new Error("VPC_PEERS/BRIDGES_TO must collapse to node edge when boxes are off");
}}
"""
    subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)


def test_layout_modes_spacing_and_live_hulls() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for frontend graph contract test")

    app_js = Path(__file__).parents[1] / "samoyed" / "api" / "static" / "app.js"
    script = f"""
require({json.dumps(str(app_js))});
const display = globalThis.SamoyedGraphDisplay;

// enforceMinSpacing separates overlapping seeds.
const nodes = [
  {{ id: "a", label: "ComputeContext", display_name: "alpha-node" }},
  {{ id: "b", label: "ComputeContext", display_name: "beta-node" }},
];
const stacked = {{ a: {{ x: 0, y: 0 }}, b: {{ x: 2, y: 2 }} }};
display.enforceMinSpacing(stacked, nodes);
const dx = Math.abs(stacked.a.x - stacked.b.x);
const dy = Math.abs(stacked.a.y - stacked.b.y);
if (dx < 40 && dy < 30) {{
  throw new Error(`expected spacing push, got dx=${{dx}} dy=${{dy}}`);
}}

// Edge attraction shortens long links without collapsing onto each other.
const far = {{
  caller: {{ x: 0, y: 0 }},
  web: {{ x: 700, y: 40 }},
}};
const attractNodes = [
  {{ id: "caller", label: "Principal", concept_type: "Identity", is_caller: true, display_name: "alice" }},
  {{ id: "web", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "web" }},
];
display.pullConnectedNeighbors(far, attractNodes, [
  {{ src: "caller", rel: "CAN_ASSUME_ROLE", dst: "web" }},
]);
const pulled = Math.hypot(far.web.x - far.caller.x, far.web.y - far.caller.y);
if (pulled >= 680) throw new Error(`expected edge pull, dist=${{pulled}}`);
if (pulled < 120) throw new Error(`edge pull too aggressive, dist=${{pulled}}`);

const graph = {{
  nodes: [
    {{ id: "caller", label: "Principal", concept_type: "Identity", is_caller: true }},
    {{ id: "web", label: "ComputeContext", concept_type: "RuntimeBinding" }},
    {{ id: "api", label: "ComputeContext", concept_type: "RuntimeBinding" }},
    {{ id: "secret", label: "Resource", concept_type: "SecretStore", is_high_value: true }},
    {{ id: "vpc1", label: "NetworkBoundary", concept_type: "NetworkBoundary",
       boundary_kind: "vpc", native_id: "aws:vpc:vpc-1", display_name: "VPC-1" }},
    {{ id: "vpc2", label: "NetworkBoundary", concept_type: "NetworkBoundary",
       boundary_kind: "vpc", native_id: "aws:vpc:vpc-2", display_name: "VPC-2" }},
  ],
  edges: [
    {{ src: "caller", rel: "CAN_ASSUME_ROLE", dst: "web" }},
    {{ src: "web", rel: "READS", dst: "secret" }},
    {{ src: "api", rel: "READS", dst: "secret" }},
    {{ src: "web", rel: "HOSTED_IN", dst: "vpc1" }},
    {{ src: "api", rel: "HOSTED_IN", dst: "vpc2" }},
  ],
}};

display.normalize(graph, {{ showBoundaryBoxes: true, showAllResourceAccess: true, layoutMode: "swim" }});
const visible = graph.nodes.filter((n) => !display.isBoundaryNode(n));
const edges = [
  {{ src: "caller", rel: "CAN_ASSUME_ROLE", dst: "web" }},
  {{ src: "web", rel: "READS", dst: "secret" }},
  {{ src: "api", rel: "READS", dst: "secret" }},
];

for (const mode of ["swim", "diamond", "helio", "space", "hierarchy", "sugiyama", "force"]) {{
  display.normalize(graph, {{ layoutMode: mode, showBoundaryBoxes: true, showAllResourceAccess: true }});
  const positions = display.computeLayout(visible, edges, "caller");
  for (const n of visible) {{
    if (!positions[n.id] || !Number.isFinite(positions[n.id].x) || !Number.isFinite(positions[n.id].y)) {{
      throw new Error(`mode ${{mode}} missing position for ${{n.id}}`);
    }}
  }}
  // Drawn nodes must not start stacked on top of each other.
  for (let i = 0; i < visible.length; i++) {{
    for (let j = i + 1; j < visible.length; j++) {{
      const a = positions[visible[i].id];
      const b = positions[visible[j].id];
      const dx = Math.abs(a.x - b.x);
      const dy = Math.abs(a.y - b.y);
      if (dx < 48 && dy < 36) {{
        throw new Error(`mode ${{mode}}: nodes overlap ${{visible[i].id}} vs ${{visible[j].id}} dx=${{dx}} dy=${{dy}}`);
      }}
    }}
  }}
}}

// Sugiyama keeps left-to-right rank order (caller left of sink).
display.normalize(graph, {{ layoutMode: "sugiyama", showBoundaryBoxes: false, showAllResourceAccess: true }});
const sugi = display.layoutSugiyama(visible, edges, "caller");
if (!(sugi.positions.caller.x < sugi.positions.secret.x)) {{
  throw new Error("sugiyama: caller must be left of high-value");
}}

// Force-directed should keep connected pairs from flying to opposite corners.
display.normalize(graph, {{ layoutMode: "force", showBoundaryBoxes: false, showAllResourceAccess: true }});
const forced = display.layoutForce(visible, edges, "caller");
const forceDist = Math.hypot(
  forced.positions.caller.x - forced.positions.web.x,
  forced.positions.caller.y - forced.positions.web.y,
);
if (forceDist > 900) {{
  throw new Error(`force layout too sparse for linked pair: ${{forceDist}}`);
}}

// Force + boxes: members of one VPC stay packed (box-as-supernode layout).
display.normalize(graph, {{ layoutMode: "force", showBoundaryBoxes: true, showAllResourceAccess: true }});
const boxedForce = display.computeLayout(visible, edges, "caller");
const boxDist = Math.hypot(
  boxedForce.web.x - boxedForce.api.x,
  boxedForce.web.y - boxedForce.api.y,
);
// web and api are in different VPCs — they may be apart. Same-VPC pack check:
const sameVpcGraph = {{
  nodes: [
    {{ id: "caller", label: "Principal", concept_type: "Identity", is_caller: true }},
    {{ id: "a", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "a-node" }},
    {{ id: "b", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "b-node" }},
    {{ id: "c", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "c-node" }},
    {{ id: "vpc1", label: "NetworkBoundary", concept_type: "NetworkBoundary",
       boundary_kind: "vpc", native_id: "aws:vpc:vpc-1", display_name: "VPC-1" }},
  ],
  edges: [
    {{ src: "caller", rel: "CAN_ASSUME_ROLE", dst: "a" }},
    {{ src: "a", rel: "CAN_REACH", dst: "b" }},
    {{ src: "b", rel: "CAN_REACH", dst: "c" }},
    {{ src: "a", rel: "HOSTED_IN", dst: "vpc1" }},
    {{ src: "b", rel: "HOSTED_IN", dst: "vpc1" }},
    {{ src: "c", rel: "HOSTED_IN", dst: "vpc1" }},
  ],
}};
display.normalize(sameVpcGraph, {{ layoutMode: "force", showBoundaryBoxes: true, showAllResourceAccess: true }});
const sameVisible = sameVpcGraph.nodes.filter((n) => !display.isBoundaryNode(n));
const sameEdges = [
  {{ src: "caller", rel: "CAN_ASSUME_ROLE", dst: "a" }},
  {{ src: "a", rel: "CAN_REACH", dst: "b" }},
  {{ src: "b", rel: "CAN_REACH", dst: "c" }},
];
const packed = display.computeLayout(sameVisible, sameEdges, "caller");
const ab = Math.hypot(packed.a.x - packed.b.x, packed.a.y - packed.b.y);
const ac = Math.hypot(packed.a.x - packed.c.x, packed.a.y - packed.c.y);
if (ab > 280 || ac > 320) {{
  throw new Error(`same-VPC force pack too loose: ab=${{ab}} ac=${{ac}}`);
}}
// Caller (unhosted) must sit outside the VPC hull.
{{
  const hulls = display.computeBoundaryHullsFromPositions(
    packed, sameVisible, display.getState().boundaries,
  );
  const vpc = hulls.find((r) => r.id === "vpc1");
  if (!vpc) throw new Error("missing vpc1 hull");
  const p = packed.caller;
  const inside = (
    p.x >= vpc.x && p.x <= vpc.x + vpc.w && p.y >= vpc.y && p.y <= vpc.y + vpc.h
  );
  if (inside) {{
    throw new Error(`unhosted caller inside vpc box: ${{JSON.stringify(p)}} box=${{JSON.stringify(vpc)}}`);
  }}
}}

// VPC-direct compute (not in a subnet) is packed as its own compact unit.
{{
  const nestGraph = {{
    nodes: [
      {{ id: "caller", label: "Principal", concept_type: "Identity", is_caller: true }},
      {{ id: "subA", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "in-subnet-a" }},
      {{ id: "subB", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "in-subnet-b" }},
      {{ id: "loose1", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "vpc-direct-1" }},
      {{ id: "loose2", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "vpc-direct-2" }},
      {{ id: "vpc1", label: "NetworkBoundary", concept_type: "NetworkBoundary",
         boundary_kind: "vpc", native_id: "aws:vpc:vpc-1", display_name: "VPC-1" }},
      {{ id: "subnet1", label: "NetworkBoundary", concept_type: "NetworkBoundary",
         boundary_kind: "subnet", native_id: "aws:subnet:subnet-1", display_name: "subnet-1" }},
    ],
    edges: [
      {{ src: "caller", rel: "CAN_ASSUME_ROLE", dst: "loose1" }},
      {{ src: "loose1", rel: "CAN_REACH", dst: "loose2" }},
      {{ src: "loose2", rel: "CAN_REACH", dst: "subA" }},
      {{ src: "subA", rel: "CAN_REACH", dst: "subB" }},
      {{ src: "subA", rel: "HOSTED_IN", dst: "subnet1" }},
      {{ src: "subB", rel: "HOSTED_IN", dst: "subnet1" }},
      {{ src: "subnet1", rel: "HOSTED_IN", dst: "vpc1" }},
      {{ src: "loose1", rel: "HOSTED_IN", dst: "vpc1" }},
      {{ src: "loose2", rel: "HOSTED_IN", dst: "vpc1" }},
    ],
  }};
  display.normalize(nestGraph, {{ layoutMode: "force", showBoundaryBoxes: true, showAllResourceAccess: true }});
  const vis = new Set(["subA", "subB", "loose1", "loose2", "caller"]);
  const drawable = display.selectDrawableBoundaries(display.getState().boundaries, vis);
  const packUnits = display.collectBoundaryPackUnits(drawable, vis);
  const direct = packUnits.find((u) => String(u.metaId).endsWith(":direct"));
  if (!direct || !direct.members.includes("loose1") || !direct.members.includes("loose2")) {{
    throw new Error(`expected VPC-direct pack unit, got ${{JSON.stringify(packUnits)}}`);
  }}
  const nestVisible = nestGraph.nodes.filter((n) => !display.isBoundaryNode(n));
  const nestEdges = nestGraph.edges.filter((e) => e.rel !== "HOSTED_IN");
  const nestPos = display.computeLayout(nestVisible, nestEdges, "caller");
  const looseDist = Math.hypot(
    nestPos.loose1.x - nestPos.loose2.x,
    nestPos.loose1.y - nestPos.loose2.y,
  );
  if (looseDist > 260) {{
    throw new Error(`VPC-direct compute pack too loose: ${{looseDist}}`);
  }}
  const subnetTop = Math.min(nestPos.subA.y, nestPos.subB.y);
  const directBottom = Math.max(nestPos.loose1.y, nestPos.loose2.y);
  if (directBottom > subnetTop - 8) {{
    throw new Error(
      `VPC-direct should sit above subnet compute: directBottom=${{directBottom}} subnetTop=${{subnetTop}}`,
    );
  }}
}}

// Account boxes must never overlap.
{{
  const acctGraph = {{
    nodes: [
      {{ id: "a1", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "a1",
         account_id: "111111111111" }},
      {{ id: "a2", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "a2",
         account_id: "222222222222" }},
      {{ id: "vpcA", label: "NetworkBoundary", concept_type: "NetworkBoundary",
         boundary_kind: "vpc", native_id: "aws:vpc:a", display_name: "vpc-a", account_id: "111111111111" }},
      {{ id: "vpcB", label: "NetworkBoundary", concept_type: "NetworkBoundary",
         boundary_kind: "vpc", native_id: "aws:vpc:b", display_name: "vpc-b", account_id: "222222222222" }},
      {{ id: "acctA", label: "ScopeBoundary", concept_type: "ScopeBoundary",
         boundary_kind: "account", native_id: "aws:account:111111111111",
         display_name: "Account 111111111111", account_id: "111111111111" }},
      {{ id: "acctB", label: "ScopeBoundary", concept_type: "ScopeBoundary",
         boundary_kind: "account", native_id: "aws:account:222222222222",
         display_name: "Account 222222222222", account_id: "222222222222" }},
    ],
    edges: [
      {{ src: "a1", rel: "HOSTED_IN", dst: "vpcA" }},
      {{ src: "vpcA", rel: "HOSTED_IN", dst: "acctA" }},
      {{ src: "a2", rel: "HOSTED_IN", dst: "vpcB" }},
      {{ src: "vpcB", rel: "HOSTED_IN", dst: "acctB" }},
      {{ src: "a1", rel: "VPC_PEERS", dst: "acctB", source: "network-enrichment" }},
      {{ src: "acctB", rel: "BRIDGES_TO", dst: "a2", source: "network-enrichment",
         boundary_crossing: true }},
    ],
  }};
  display.normalize(acctGraph, {{ layoutMode: "space", showBoundaryBoxes: true, showAllResourceAccess: true }});
  const acctVisible = acctGraph.nodes.filter((n) => !display.isBoundaryNode(n));
  const seeded = {{ a1: {{ x: 0, y: 0 }}, a2: {{ x: 10, y: 10 }} }};
  display.separateAccountBoxesNeverOverlap(seeded, acctVisible, display.getState().boundaries);
  const acctHulls = display.computeBoundaryHullsFromPositions(
    seeded, acctVisible, display.getState().boundaries,
  );
  const ha = acctHulls.find((h) => h.id === "acctA");
  const hb = acctHulls.find((h) => h.id === "acctB");
  if (!ha || !hb) throw new Error("missing account hulls");
  const aox = Math.min(ha.x + ha.w, hb.x + hb.w) - Math.max(ha.x, hb.x);
  const aoy = Math.min(ha.y + ha.h, hb.y + hb.h) - Math.max(ha.y, hb.y);
  if (aox > 0 && aoy > 0) {{
    throw new Error(`account boxes overlap: ${{JSON.stringify(ha)}} vs ${{JSON.stringify(hb)}}`);
  }}
}}
void boxDist;

display.normalize(graph, {{ layoutMode: "diamond", showBoundaryBoxes: false, showAllResourceAccess: true }});
const diamond = display.layoutConnectedComponent(visible, edges, "caller");
if (!(diamond.positions.caller.x < diamond.positions.secret.x)) {{
  throw new Error("diamond: caller must be left of high-value");
}}

// Live hulls wrap members — layout does not own frozen box rects.
display.normalize(graph, {{ layoutMode: "swim", showBoundaryBoxes: true, showAllResourceAccess: true }});
const positions = display.computeLayout(visible, edges, "caller");
const hulls = display.computeBoundaryHullsFromPositions(
  positions, visible, display.getState().boundaries,
);
const vpc1 = hulls.find((r) => r.id === "vpc1");
const vpc2 = hulls.find((r) => r.id === "vpc2");
if (!vpc1 || !vpc2) throw new Error("missing vpc hulls");
function inside(rect, p, pad = 8) {{
  return (
    p.x >= rect.x + pad
    && p.x <= rect.x + rect.w - pad
    && p.y >= rect.y + pad
    && p.y <= rect.y + rect.h - pad
  );
}}
if (!inside(vpc1, positions.web)) {{
  throw new Error(`web outside vpc1 hull: node=${{JSON.stringify(positions.web)}} box=${{JSON.stringify(vpc1)}}`);
}}
if (!inside(vpc2, positions.api)) {{
  throw new Error(`api outside vpc2 hull: node=${{JSON.stringify(positions.api)}} box=${{JSON.stringify(vpc2)}}`);
}}
// Sibling VPC boxes must not start overlaid.
{{
  const gap = 20;
  const ox = Math.min(vpc1.x + vpc1.w, vpc2.x + vpc2.w) - Math.max(vpc1.x, vpc2.x);
  const oy = Math.min(vpc1.y + vpc1.h, vpc2.y + vpc2.h) - Math.max(vpc1.y, vpc2.y);
  if (ox > -gap && oy > -gap) {{
    throw new Error(`vpc boxes overlap: vpc1=${{JSON.stringify(vpc1)}} vpc2=${{JSON.stringify(vpc2)}}`);
  }}
}}
// Explicit VPC separation helper from a stacked seed.
{{
  const stacked = {{ web: {{ x: 0, y: 0 }}, api: {{ x: 5, y: 5 }} }};
  display.separateVpcBoxesPreferNoOverlap(
    stacked, visible, display.getState().boundaries,
  );
  const sep = display.computeBoundaryHullsFromPositions(
    stacked, visible, display.getState().boundaries,
  );
  const s1 = sep.find((r) => r.id === "vpc1");
  const s2 = sep.find((r) => r.id === "vpc2");
  const sox = Math.min(s1.x + s1.w, s2.x + s2.w) - Math.max(s1.x, s2.x);
  const soy = Math.min(s1.y + s1.h, s2.y + s2.h) - Math.max(s1.y, s2.y);
  if (sox > 0 && soy > 0) {{
    throw new Error(`separateVpcBoxesPreferNoOverlap left overlap`);
  }}
}}
// Sibling subnets should not overlap.
{{
  const subGraph = {{
    nodes: [
      {{ id: "n1", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "n1" }},
      {{ id: "n2", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "n2" }},
      {{ id: "n3", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "n3" }},
      {{ id: "n4", label: "ComputeContext", concept_type: "RuntimeBinding", display_name: "n4" }},
      {{ id: "vpc1", label: "NetworkBoundary", concept_type: "NetworkBoundary",
         boundary_kind: "vpc", native_id: "aws:vpc:v", display_name: "VPC" }},
      {{ id: "sub1", label: "NetworkBoundary", concept_type: "NetworkBoundary",
         boundary_kind: "subnet", native_id: "aws:subnet:s1", display_name: "sub-1" }},
      {{ id: "sub2", label: "NetworkBoundary", concept_type: "NetworkBoundary",
         boundary_kind: "subnet", native_id: "aws:subnet:s2", display_name: "sub-2" }},
    ],
    edges: [
      {{ src: "n1", rel: "HOSTED_IN", dst: "sub1" }},
      {{ src: "n2", rel: "HOSTED_IN", dst: "sub1" }},
      {{ src: "n3", rel: "HOSTED_IN", dst: "sub2" }},
      {{ src: "n4", rel: "HOSTED_IN", dst: "sub2" }},
      {{ src: "sub1", rel: "HOSTED_IN", dst: "vpc1" }},
      {{ src: "sub2", rel: "HOSTED_IN", dst: "vpc1" }},
    ],
  }};
  display.normalize(subGraph, {{ layoutMode: "space", showBoundaryBoxes: true, showAllResourceAccess: true }});
  const subVisible = subGraph.nodes.filter((n) => !display.isBoundaryNode(n));
  const stackedSubs = {{
    n1: {{ x: 0, y: 0 }}, n2: {{ x: 40, y: 0 }},
    n3: {{ x: 10, y: 10 }}, n4: {{ x: 50, y: 10 }},
  }};
  display.separateSubnetBoxesPreferNoOverlap(
    stackedSubs, subVisible, display.getState().boundaries,
  );
  const subHulls = display.computeBoundaryHullsFromPositions(
    stackedSubs, subVisible, display.getState().boundaries,
  );
  const hs1 = subHulls.find((r) => r.id === "sub1");
  const hs2 = subHulls.find((r) => r.id === "sub2");
  if (!hs1 || !hs2) throw new Error("missing subnet hulls");
  const ssx = Math.min(hs1.x + hs1.w, hs2.x + hs2.w) - Math.max(hs1.x, hs2.x);
  const ssy = Math.min(hs1.y + hs1.h, hs2.y + hs2.h) - Math.max(hs1.y, hs2.y);
  if (ssx > 0 && ssy > 0) {{
    throw new Error("separateSubnetBoxesPreferNoOverlap left overlap");
  }}
}}
// Edge neighbors must stay near even with box separation on (force default).
{{
  display.normalize(graph, {{ layoutMode: "force", showBoundaryBoxes: true, showAllResourceAccess: true }});
  const nearPos = display.computeLayout(visible, edges, "caller");
  const callerWeb = Math.hypot(
    nearPos.caller.x - nearPos.web.x,
    nearPos.caller.y - nearPos.web.y,
  );
  const webSecret = Math.hypot(
    nearPos.web.x - nearPos.secret.x,
    nearPos.web.y - nearPos.secret.y,
  );
  if (callerWeb > 520) {{
    throw new Error(`caller↔web too far after box rules: ${{callerWeb}}`);
  }}
  if (webSecret > 560) {{
    throw new Error(`web↔secret too far after box rules: ${{webSecret}}`);
  }}
}}
// Restore original graph boundaries after the subnet fixture mutated state.
display.normalize(graph, {{ layoutMode: "swim", showBoundaryBoxes: true, showAllResourceAccess: true }});
// Drag/relayout simulation: hull must follow moved members.
positions.web.x += 400;
positions.web.y += 300;
const moved = display.computeBoundaryHullsFromPositions(
  positions, visible, display.getState().boundaries,
);
const vpc1b = moved.find((r) => r.id === "vpc1");
if (!inside(vpc1b, positions.web)) {{
  throw new Error("hull must resize around moved member");
}}

// Hit-test prefers the innermost (smallest) overlapping box.
const nested = [
  {{ id: "acct", kind: "account", x: 0, y: 0, w: 400, h: 300 }},
  {{ id: "vpc", kind: "vpc", x: 40, y: 40, w: 200, h: 160 }},
];
const hit = display.findBoundaryBoxAt(nested, 100, 100);
if (!hit || hit.id !== "vpc") {{
  throw new Error(`expected innermost vpc hit, got ${{hit && hit.id}}`);
}}
if (display.findBoundaryBoxAt(nested, -10, -10) !== null) {{
  throw new Error("miss should return null");
}}
"""
    result = subprocess.run([node, "-e", script], capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
