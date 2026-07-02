"""
Command-line normalization helpers.

Detection rules match against attacker-controlled command lines that can be
padded with extra whitespace or embedded null bytes to dodge naive substring
checks. These helpers produce a canonical ``process.normalized_command`` field
for matching while leaving the raw ``process.command_line`` untouched so it is
preserved verbatim as alert evidence (and for dedup hashing).

Case is preserved here — the evaluator already lowercases both sides at match
time, so lowercasing now would only lose evidence fidelity in the normalized
field.
"""
import re
from typing import Any, Dict

_WHITESPACE_RUN = re.compile(r"\s+")


def normalize_command_line(raw: str) -> str:
    """Collapse whitespace runs to single spaces, drop null bytes, and strip.

    Returns "" for falsy input. Never raises.
    """
    if not raw:
        return ""
    text = str(raw).replace("\x00", " ")
    return _WHITESPACE_RUN.sub(" ", text).strip()


def enrich_process_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    """Add ``process.normalized_command`` when a raw command line is present.

    Idempotent and safe on malformed events (missing/oddly-typed ``process``).
    Returns the same event dict for convenience.
    """
    process = event.get("process")
    if not isinstance(process, dict):
        return event

    command_line = process.get("command_line")
    if command_line:
        process["normalized_command"] = normalize_command_line(command_line)

    return event
