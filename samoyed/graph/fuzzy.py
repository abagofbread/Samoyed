"""Fuzzy graph node resolution for Terraform / analyst name hints.

Exact ARN/id match is ideal but collectors usually only know rough names
(``RDS_CREDS``, ``ecs-task-role``, ``aws-goat-db``). This module scores candidates
and returns a unique best match above a threshold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Iterable

from samoyed.graph.model import GraphNode, GraphSnapshot

_SPLIT = re.compile(r"[^a-z0-9]+")
_SECRET_SUFFIX = re.compile(r"^(?P<name>.+)-(?P<suf>[A-Za-z0-9]{6})$")
_ARN_SECRET = re.compile(r":secret:([^:\s]+)", re.IGNORECASE)
_ARN_ROLE = re.compile(r":role/([^/\s]+)", re.IGNORECASE)
_ARN_USER = re.compile(r":user/([^/\s]+)", re.IGNORECASE)
_ARN_INSTANCE = re.compile(r":db:([^/\s]+)", re.IGNORECASE)

# Minimum score to accept a fuzzy hit when it is uniquely best.
DEFAULT_MIN_SCORE = 0.72


@dataclass(frozen=True)
class FuzzyMatch:
    node_id: str
    score: float
    reason: str


def normalize_name(value: str) -> str:
    return _SPLIT.sub("", (value or "").lower())


def tokenize(value: str) -> frozenset[str]:
    parts = [p for p in _SPLIT.split((value or "").lower()) if len(p) >= 2]
    return frozenset(parts)


def leaf_name(value: str) -> str:
    """Best-effort human leaf from an ARN, native id, or path."""
    text = (value or "").strip()
    if not text:
        return ""
    for pattern in (_ARN_SECRET, _ARN_ROLE, _ARN_USER, _ARN_INSTANCE):
        match = pattern.search(text)
        if match:
            return _strip_aws_secret_suffix(match.group(1))
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    return _strip_aws_secret_suffix(text)


def _strip_aws_secret_suffix(name: str) -> str:
    """Secrets Manager appends a 6-char suffix: ``RDS_CREDS-AbCdEf`` → ``RDS_CREDS``."""
    match = _SECRET_SUFFIX.match(name)
    if match and len(match.group("name")) >= 3:
        return match.group("name")
    return name


def node_identity_strings(node: GraphNode) -> list[str]:
    """Strings worth comparing for name matching."""
    props = node.props or {}
    values = [
        node.node_id,
        str(props.get("arn") or ""),
        str(props.get("native_id") or ""),
        str(props.get("display_name") or ""),
        str(props.get("name") or ""),
        str(props.get("bucket_name") or ""),
        str(props.get("function_name") or ""),
        str(props.get("secret_name") or ""),
        str(props.get("db_instance_identifier") or ""),
        str(props.get("identifier") or ""),
        str(props.get("cluster_name") or ""),
        str(props.get("role_name") or ""),
    ]
    # Derived leaves
    extra: list[str] = []
    for value in list(values):
        leaf = leaf_name(value)
        if leaf and leaf not in values:
            extra.append(leaf)
    return [v for v in values + extra if v and v != "None"]


def is_wildcard_stub(node: GraphNode) -> bool:
    native = str((node.props or {}).get("native_id") or node.node_id or "")
    return "*" in native or native.endswith(":*") or ":*:" in native


def score_node_against_ref(
    ref: str,
    node: GraphNode,
    *,
    prefer_concepts: Iterable[str] | None = None,
) -> FuzzyMatch | None:
    """Score one node against a ref. Returns None if too weak / stub-only."""
    needle = (ref or "").strip()
    if not needle:
        return None
    if is_wildcard_stub(node):
        return None

    needle_l = needle.lower()
    needle_leaf = leaf_name(needle).lower() or needle_l
    needle_norm = normalize_name(needle_leaf)
    needle_tokens = tokenize(needle_leaf)
    prefer = {c.lower() for c in (prefer_concepts or [])}

    best = 0.0
    reason = "none"
    for field in node_identity_strings(node):
        field_l = field.lower()
        field_leaf = leaf_name(field).lower()
        field_norm = normalize_name(field_leaf)

        if field_l == needle_l or field_leaf == needle_leaf:
            score = 1.0
            why = "exact"
        elif field_norm and field_norm == needle_norm:
            score = 0.98
            why = "normalized"
        elif field_l.endswith("/" + needle_leaf) or field_l.endswith(":" + needle_leaf):
            score = 0.94
            why = "arn-leaf"
        elif needle_leaf and (
            field_leaf.startswith(needle_leaf + "-")
            or field_l.startswith(needle_leaf + "-")
            or f":{needle_leaf}-" in field_l
            or f"/{needle_leaf}-" in field_l
        ):
            # Secrets Manager style name-xxxxxx
            score = 0.92
            why = "prefixed-name"
        elif needle_leaf and len(needle_leaf) >= 4 and needle_leaf in field_l:
            score = 0.78 + min(0.1, len(needle_leaf) / 100.0)
            why = "substring"
        else:
            seq = SequenceMatcher(None, needle_norm, field_norm).ratio() if needle_norm and field_norm else 0.0
            field_tokens = tokenize(field_leaf)
            jaccard = (
                len(needle_tokens & field_tokens) / len(needle_tokens | field_tokens)
                if needle_tokens and field_tokens
                else 0.0
            )
            # Require meaningful token overlap for jaccard path
            if jaccard and len(needle_tokens & field_tokens) == 0:
                jaccard = 0.0
            score = max(seq * 0.9, jaccard * 0.85)
            why = "similarity" if score >= DEFAULT_MIN_SCORE else "weak"
            if score < 0.55:
                continue

        if score > best:
            best = score
            reason = why

    if best <= 0:
        return None

    # Concept preference boost (does not invent matches, only breaks ties)
    concept = str((node.props or {}).get("concept_type") or "").lower()
    native_kind = str((node.props or {}).get("native_kind") or "").lower()
    if prefer:
        if concept in prefer or native_kind in prefer:
            best = min(1.0, best + 0.04)
            reason = f"{reason}+concept"

    if best < 0.55:
        return None
    return FuzzyMatch(node_id=node.node_id, score=best, reason=reason)


def fuzzy_match_nodes(
    graph: GraphSnapshot,
    ref: str,
    *,
    min_score: float = DEFAULT_MIN_SCORE,
    limit: int = 5,
    prefer_concepts: Iterable[str] | None = None,
) -> list[FuzzyMatch]:
    """Return scored matches for ``ref``, best first."""
    matches: list[FuzzyMatch] = []
    for _node_id, node in graph.nodes.items():
        if node.label == "CollectionSession":
            continue
        hit = score_node_against_ref(ref, node, prefer_concepts=prefer_concepts)
        if hit and hit.score >= min_score:
            matches.append(hit)
    matches.sort(key=lambda m: (-m.score, m.node_id))
    return matches[:limit]


def fuzzy_resolve_node(
    graph: GraphSnapshot,
    ref: str | None,
    *,
    min_score: float = DEFAULT_MIN_SCORE,
    prefer_concepts: Iterable[str] | None = None,
    allow_ambiguous: bool = False,
) -> str | None:
    """
    Resolve ``ref`` to a single node id.

    Requires a clear winner (best score uniquely ahead, or sole candidate)
    unless ``allow_ambiguous`` is set.
    """
    if not ref or not str(ref).strip():
        return None
    matches = fuzzy_match_nodes(
        graph,
        str(ref).strip(),
        min_score=min_score,
        limit=5,
        prefer_concepts=prefer_concepts,
    )
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0].node_id
    best, second = matches[0], matches[1]
    if best.score >= second.score + 0.05 or best.reason.startswith("exact") or best.reason.startswith("normalized"):
        return best.node_id
    if allow_ambiguous:
        return best.node_id
    return None


def prefer_concepts_for_material(kind: str | None) -> tuple[str, ...]:
    """Concept bias when resolving enrichment ``name_hints``."""
    key = (kind or "").lower()
    if key in {"database_connection_string", "generic_credential_file"}:
        # DB passwords / connection strings → stores first, then secrets/roles.
        return (
            "datastore",
            "secretstore",
            "rds",
            "dbinstance",
            "secret",
            "identity",
            "role",
            "user",
        )
    if key.startswith("aws_") or "secret" in key:
        return ("identity", "secretstore", "secret", "role", "user")
    if "kube" in key or "k8s" in key:
        return ("identity", "workload")
    return ()
