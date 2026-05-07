"""
Auditd event aggregation layer.

Linux auditd represents one security-relevant activity across multiple
record types that share the same audit event ID embedded in:

    msg=audit(1710000000.123:456):

SYSCALL   → process identity (pid, uid, exe, comm)
EXECVE    → command-line arguments → process.command_line
PROCTITLE → hex-encoded full command → process.command_line
PATH      → file access → file.path, event.action

This module groups those related records by (agent_id, audit_event_id),
deep-merges their normalised fields, and returns completed events once the
TTL expires so the detection engine receives one unified event instead of
several incomplete fragments.

Environment variables:
    AUDIT_AGGREGATION_TTL_SECONDS   float, default 2.0
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("detection.audit_event_aggregator")

# Regex to extract the audit event identifier from the message header.
# Matches: msg=audit(1710000000.123:456):
_AUDIT_ID_RE = re.compile(r"msg=audit\((\d+\.\d+:\d+)\)")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


class AuditEventAggregator:
    """
    Thread-safe in-memory buffer that groups auditd records by audit event ID
    and returns merged events once the TTL expires.
    """

    def __init__(self, ttl_seconds: float = 2.0) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        # (agent_id, audit_event_id) → deep-merged normalised event dict
        self._buffer: Dict[Tuple[str, str], dict] = {}
        # (agent_id, audit_event_id) → epoch when first record arrived
        self._first_seen: Dict[Tuple[str, str], float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_audit_event_id(self, message: str) -> Optional[str]:
        """Return the 'timestamp:serial' audit event ID, or None."""
        m = _AUDIT_ID_RE.search(message)
        return m.group(1) if m else None

    def add_record(
        self,
        agent_id: str,
        audit_event_id: str,
        normalized_record: dict,
    ) -> List[dict]:
        """
        Add a normalised record to its aggregation group.

        Returns a list of fully-expired merged events that are ready for
        detection evaluation.  Callers should run detection on each returned
        event immediately.
        """
        key = (agent_id, audit_event_id)
        now = time.time()

        with self._lock:
            # Flush any groups whose TTL has elapsed before adding the new record.
            completed = self._flush_expired_locked(now)

            if key in self._buffer:
                self._buffer[key] = self._deep_merge(
                    self._buffer[key], normalized_record
                )
            else:
                self._first_seen[key] = now
                self._buffer[key] = dict(normalized_record)

            # Annotate the buffer entry with aggregation metadata.
            entry = self._buffer[key]
            entry.setdefault("audit", {})
            entry["audit"]["event_id"] = audit_event_id
            entry["audit"]["record_count"] = entry["audit"].get("record_count", 0) + 1

        return completed

    def flush_expired(self) -> List[dict]:
        """Return and remove all groups whose TTL has elapsed."""
        with self._lock:
            return self._flush_expired_locked(time.time())

    def flush_all(self) -> List[dict]:
        """Return and remove every buffered group regardless of TTL."""
        with self._lock:
            completed = list(self._buffer.values())
            self._buffer.clear()
            self._first_seen.clear()
        return completed

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _flush_expired_locked(self, now: float) -> List[dict]:
        """Must be called with self._lock held."""
        expired_keys = [
            k for k, ts in self._first_seen.items() if now - ts >= self._ttl
        ]
        completed: List[dict] = []
        for k in expired_keys:
            merged = self._buffer.pop(k, None)
            self._first_seen.pop(k, None)
            if merged is not None:
                completed.append(merged)
        return completed

    def _deep_merge(self, base: dict, incoming: dict) -> dict:
        """
        Recursively merge *incoming* into a copy of *base*.

        Rules:
        - Nested dicts are merged recursively.
        - A non-empty value in *base* is kept; an incoming value is only
          used to fill a missing or falsy base value.
        - Keys absent from *base* are added from *incoming*.

        This ensures that PATH record fields (file.path, event.action) and
        EXECVE/PROCTITLE fields (process.command_line) are both preserved
        regardless of arrival order.
        """
        result = dict(base)
        for key, value in incoming.items():
            if key in result:
                existing = result[key]
                if isinstance(existing, dict) and isinstance(value, dict):
                    result[key] = self._deep_merge(existing, value)
                elif not existing and value:
                    # Overwrite falsy/empty with useful incoming value.
                    result[key] = value
                # else: keep existing non-empty value
            else:
                result[key] = value
        return result


# ---------------------------------------------------------------------------
# Module-level singleton (mirrors correlation_engine.py pattern)
# ---------------------------------------------------------------------------

_audit_event_aggregator: Optional[AuditEventAggregator] = None


def get_audit_event_aggregator() -> AuditEventAggregator:
    global _audit_event_aggregator
    if _audit_event_aggregator is None:
        ttl = _env_float("AUDIT_AGGREGATION_TTL_SECONDS", 2.0)
        _audit_event_aggregator = AuditEventAggregator(ttl_seconds=ttl)
    return _audit_event_aggregator
