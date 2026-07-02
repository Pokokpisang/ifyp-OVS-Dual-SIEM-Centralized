"""
Loader for Python-driven detection engines' descriptive metadata.

The correlation and SSH-brute-force engines implement their detection logic in
Python (multi-event / threshold-over-window patterns that a single-event YAML
rule cannot express). Their alert *metadata* — rule id, name, MITRE mapping, base
risk, severity — is defined in `detection/engine_meta/*.yaml` so it follows the
same detection-as-code governance as the YAML rules. This directory is a sibling
of `rules/`, so `RuleLoader` never evaluates these files.
"""
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import yaml

_META_DIR = Path(__file__).parent.parent / "engine_meta"


@lru_cache(maxsize=None)
def load_engine_metadata(name: str) -> Dict[str, Any]:
    """Load `engine_meta/<name>.yaml` as a dict.

    Returns {} on any error (missing file, bad YAML, non-mapping content) so
    callers fall back to their built-in defaults and detection never breaks.
    """
    path = _META_DIR / f"{name}.yaml"
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, yaml.YAMLError):
        return {}


def mitre_id(meta: Dict[str, Any], kind: str, default: str) -> str:
    """Extract meta['mitre'][kind]['id'] safely, falling back to *default*.

    kind is 'tactic' or 'technique'.
    """
    node = (meta.get("mitre") or {}).get(kind) or {}
    return node.get("id", default)
