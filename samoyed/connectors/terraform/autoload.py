"""Discover companion enrichment files next to Terraform labs."""

from __future__ import annotations

from pathlib import Path

# Accepted companion filenames under a terraform lab tree.
ENRICHMENT_BASENAMES = frozenset({"enrichment.json"})
ENRICHMENT_SUFFIX = ".enrichment.json"


def discover_companion_enrichments(path: Path) -> list[Path]:
    """Find enrichment JSON files accompanying a terraform path.

    Conventions (any match is applied, sorted for stability)::

        <dir>/enrichment.json
        <dir>/**/enrichment.json
        <dir>/**/*.enrichment.json

    When ``path`` is a single ``.tfstate`` / ``.tf`` file, also check the
    sibling ``enrichment.json`` and ``<stem>.enrichment.json``.
    """
    path = Path(path)
    found: list[Path] = []
    if path.is_file():
        sibling = path.with_name("enrichment.json")
        if sibling.is_file():
            found.append(sibling)
        stem_enrich = path.with_name(f"{path.stem}{ENRICHMENT_SUFFIX}")
        if stem_enrich.is_file():
            found.append(stem_enrich)
        # Also ``foo.tfstate`` → ``foo.enrichment.json`` when stem includes dots.
        if path.name.endswith(".tfstate"):
            alt = path.with_name(path.name[: -len(".tfstate")] + ENRICHMENT_SUFFIX)
            if alt.is_file() and alt not in found:
                found.append(alt)
        return sorted({p.resolve() for p in found})

    if not path.is_dir():
        return []

    for candidate in path.rglob("*"):
        if not candidate.is_file():
            continue
        name = candidate.name
        if name in ENRICHMENT_BASENAMES or name.endswith(ENRICHMENT_SUFFIX):
            found.append(candidate)
    return sorted({p.resolve() for p in found})


def apply_companion_enrichments(session_store: object, session_id: str, path: Path) -> list[dict]:
    """Apply all discovered companion enrichments; return per-file stats."""
    results: list[dict] = []
    apply = getattr(session_store, "apply_enrichment", None)
    if not callable(apply):
        return results
    for enrich_path in discover_companion_enrichments(path):
        stats = apply(session_id, enrich_path.read_bytes())
        results.append({"path": str(enrich_path), **(stats or {})})
    return results
