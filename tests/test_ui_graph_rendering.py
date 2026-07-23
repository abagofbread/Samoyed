from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


def test_privesc_self_loop_and_leaf_resource_filter_contract() -> None:
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
    {{ src: "principal", rel: "READS", dst: "kms" }},
    {{ src: "principal", rel: "READS", dst: "crown" }},
  ],
}};

const compact = display.normalize(graph, {{ showAllResourceAccess: false }});
const loops = compact.edges.filter(
  (edge) => edge.rel === "CAN_PRIVESC_TO"
    && edge.src === "principal"
    && edge.dst === "principal"
);
if (loops.length !== 2) throw new Error(`expected 2 privesc self-loops, got ${{loops.length}}`);
if (compact.nodes.some((node) => node.id === "kms")) throw new Error("leaf KMS resource rendered");
if (!compact.nodes.some((node) => node.id === "crown")) throw new Error("high-value leaf hidden");

const visLoops = display.buildEdges(compact.edges, compact.nodes)
  .filter((edge) => edge.from === edge.to);
if (visLoops.length !== 2 || visLoops.some((edge) => !edge.selfReference)) {{
  throw new Error("privesc self-reference rendering missing");
}}
if (visLoops[0].selfReference.size === visLoops[1].selfReference.size) {{
  throw new Error("parallel self-loops overlap exactly");
}}

const expanded = display.normalize(graph, {{ showAllResourceAccess: true }});
if (!expanded.nodes.some((node) => node.id === "kms")) throw new Error("resource toggle failed");
"""
    subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)
