from __future__ import annotations

from typing import Any

from samoyed.graph.model import GraphSnapshot
from samoyed.path_engine.models import PathResult


def explain_path(graph: GraphSnapshot, path: PathResult) -> dict[str, Any]:
    steps_out: list[dict[str, Any]] = []
    for step in path.steps:
        src = graph.nodes.get(step.src_id)
        dst = graph.nodes.get(step.dst_id)
        src_name = _display(src, step.src_id)
        dst_name = _display(dst, step.dst_id)
        evidence = step.evidence or (dst.props if dst else {})
        narrative = _narrative(step, src_name, dst_name, evidence)
        steps_out.append(
            {
                "step": step.step_index,
                "relationship": step.rel_type,
                "confidence": step.confidence,
                "from": {"node_id": step.src_id, "display": src_name, "concept": _concept(src)},
                "to": {"node_id": step.dst_id, "display": dst_name, "concept": _concept(dst)},
                "narrative": narrative,
                "evidence": evidence,
            }
        )

    target = path.target_match or {}
    return {
        "path_id": path.path_id,
        "score": path.score,
        "summary": _summary(path, steps_out),
        "target": target,
        "steps": steps_out,
    }


def _narrative(step, src_name: str, dst_name: str, evidence: dict[str, Any]) -> str:
    if step.rel_type == "CAN_PRIVESC_TO" and evidence.get("attack_outcome"):
        outcome = evidence.get("outcome_display") or evidence.get("attack_outcome") or "administrator access"
        pattern = evidence.get("pattern_name")
        if pattern:
            return f"{src_name} can escalate via {pattern} to {outcome}"
        return f"{src_name} can escalate to {outcome}"
    if step.rel_type == "CAN_PRIVESC_TO" and evidence.get("pattern_name"):
        return (
            f"{src_name} can escalate privileges ({evidence['pattern_name']}) "
            f"to reach {dst_name}"
        )
    if step.rel_type == "EXECUTES_AS":
        return f"{src_name} runs as {dst_name} (execution role / instance profile)"
    if step.rel_type == "LOGGED_IN_AS":
        return f"{src_name} has interactive session for {dst_name} (token theft / mimikatz)"
    if step.rel_type == "STORES_CREDS_FOR":
        return f"{src_name} stores cached credentials for {dst_name}"
    if step.rel_type == "CAN_STEAL_CREDS_FROM":
        return f"{src_name} can harvest credentials for {dst_name} from disk or memory"
    if step.rel_type == "CAN_ASSUME_ROLE":
        return f"{src_name} can assume role {dst_name}"
    return f"{src_name} can reach {dst_name} via {step.rel_type}"


def _display(node, fallback: str) -> str:
    if not node:
        return fallback
    for key in ("display_name", "native_id", "arn", "name"):
        value = node.props.get(key)
        if value:
            return str(value)
    return node.node_id


def _concept(node) -> str | None:
    if not node:
        return None
    return node.props.get("concept_type")


def _summary(path: PathResult, steps: list[dict[str, Any]]) -> str:
    if not steps:
        return "Empty path"
    first = steps[0]["from"]["display"]
    last = steps[-1]["to"]["display"]
    rel_chain = " → ".join(s["relationship"] for s in steps)
    return f"From {first} to {last} ({len(steps)} hop(s): {rel_chain}), score {path.score}"
