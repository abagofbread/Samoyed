from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from samoyed.enumerators.contracts import ConceptEnumerator


def discover_enumerators() -> list[ConceptEnumerator]:
    found: list[ConceptEnumerator] = []
    found.extend(_from_entry_points())
    found.extend(_from_samoyed_dir())
    return found


def _from_entry_points() -> list[ConceptEnumerator]:
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return []
    eps = entry_points()
    group = eps.select(group="samoyed.enumerators") if hasattr(eps, "select") else eps.get("samoyed.enumerators", [])
    result: list[ConceptEnumerator] = []
    for ep in group:
        try:
            obj = ep.load()
            result.append(obj() if callable(obj) else obj)
        except Exception:
            continue
    return result


def _from_samoyed_dir() -> list[ConceptEnumerator]:
    base = Path.cwd() / ".samoyed" / "enumerators"
    if not base.is_dir():
        return []
    result: list[ConceptEnumerator] = []
    for path in sorted(base.glob("*.py")):
        if path.name.startswith("_"):
            continue
        mod_name = f"samoyed_ext_{path.stem}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if not spec or not spec.loader:
            continue
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception:
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if hasattr(obj, "enumerate") and hasattr(obj, "concept"):
                try:
                    result.append(obj() if isinstance(obj, type) else obj)
                except Exception:
                    pass
    return result


def init_extension(kind: str, name: str, target_dir: Path | None = None) -> Path:
    base = target_dir or Path.cwd() / ".samoyed"
    if kind == "enumerator":
        dest = base / "enumerators" / f"{name}.py"
        dest.parent.mkdir(parents=True, exist_ok=True)
        name_class = "".join(p.capitalize() for p in name.replace("-", "_").split("_"))
        dest.write_text(
            ENUMERATOR_STUB.format(name=name, name_class=name_class),
            encoding="utf-8",
        )
        return dest
    if kind == "connector":
        dest = base / "connectors" / f"{name}.py"
        dest.parent.mkdir(parents=True, exist_ok=True)
        name_class = "".join(p.capitalize() for p in name.replace("-", "_").split("_"))
        dest.write_text(
            CONNECTOR_STUB.format(name=name, name_class=name_class),
            encoding="utf-8",
        )
        return dest
    raise ValueError(f"Unknown extension kind: {kind}")


ENUMERATOR_STUB = '''"""Custom Samoyed enumerator — emit ConceptArtifact objects."""

from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType
from samoyed.credentials.protocol import EnumContext


class {name_class}Enumerator:
    concept = ConceptType.IDENTITY
    name = "{name}"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id="custom:example",
            scope_id=ctx.scope.scope_id,
            properties={{"native_kind": "Custom", "note": "replace me"}},
            evidence=Evidence("custom:enum", {{"source": "{name}"}}),
            confidence=ConfidenceType.EXPLICIT,
        )
'''

CONNECTOR_STUB = '''"""Custom Samoyed connector — import external graph data into ConceptArtifacts."""

from __future__ import annotations

from typing import Iterator

from samoyed.cloud.artifacts import ConceptArtifact, Evidence
from samoyed.cloud.concepts import CloudProvider, ConceptType, ConfidenceType


def import_{name}(**, ctx) -> Iterator[ConceptArtifact]:
    """Yield ConceptArtifact rows from your external source."""
    yield ConceptArtifact(
        concept_type=ConceptType.IDENTITY,
        provider=CloudProvider.AWS,
        native_id="custom:connector:example",
        scope_id="aws:account:unknown",
        properties={{"native_kind": "Custom", "source": "{name}"}},
        evidence=Evidence("custom:connector", {{"source": "{name}"}}),
        confidence=ConfidenceType.EXPLICIT,
    )
'''
