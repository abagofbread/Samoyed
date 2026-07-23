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
