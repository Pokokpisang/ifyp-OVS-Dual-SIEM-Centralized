"""
In-memory threshold engine for detecting SSH brute-force patterns (T1110).

Counts failed SSH authentication events per (agent_id, source_ip) and fires a
SSHBruteForceMatch when the failure count exceeds SSH_BF_THRESHOLD within
SSH_BF_WINDOW_SECONDS.

Feature flags (env vars):
  ENABLE_SSH_BRUTEFORCE_ENGINE   default: "true"
  SSH_BF_THRESHOLD               default: 5
  SSH_BF_WINDOW_SECONDS          default: 60
  SSH_BF_DEDUP_SECONDS           default: 60
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .engine_metadata import load_engine_metadata, mitre_id

logger = logging.getLogger("detection.ssh_bruteforce_engine")

# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in ("1", "true", "yes")

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default

ENABLE_SSH_BRUTEFORCE_ENGINE: bool = _env_bool("ENABLE_SSH_BRUTEFORCE_ENGINE", True)
SSH_BF_THRESHOLD: int = _env_int("SSH_BF_THRESHOLD", 5)
SSH_BF_WINDOW_SECONDS: int = _env_int("SSH_BF_WINDOW_SECONDS", 60)
SSH_BF_DEDUP_SECONDS: int = _env_int("SSH_BF_DEDUP_SECONDS", 60)
# Distinct usernames from one source within the window that indicate password
# spraying (rather than targeting a single account).
SSH_BF_SPRAY_USER_THRESHOLD: int = _env_int("SSH_BF_SPRAY_USER_THRESHOLD", 3)

# Severity/risk escalation bands, expressed relative to the threshold.
SSH_BF_SEVERE_MULTIPLIER = 3      # count >= threshold*3 -> severe
SSH_BF_ELEVATED_MULTIPLIER = 2    # count >= threshold*2 -> elevated
SSH_BF_RISK_SEVERE = 75
SSH_BF_RISK_ELEVATED = 60
SSH_BF_RISK_BASE = 45
SSH_BF_SPRAY_RISK_BONUS = 10

# Max DB rows to scan when counting recent failures (bounds query cost).
SSH_BF_DB_ROW_LIMIT = 500

# Matches the parser's username extraction ("for [invalid user ]<name>").
_SSH_USER_RE = re.compile(r"for (?:invalid user )?(\w+)")

# Descriptive alert metadata is defined in engine_meta/ (detection-as-code); the
# hardcoded literals in SSHBruteForceMatch are only fallbacks. risk_score/severity
# here are the BASE — evaluate() escalates them via the count/spray bands.
_META = load_engine_metadata("ssh_bruteforce_threshold")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SSHFailureEvent:
    """A single failed SSH authentication event stored in the rolling buffer."""
    timestamp: float        # UNIX epoch seconds
    agent_id: str
    source_ip: str
    user_name: Optional[str] = None


@dataclass
class SSHBruteForceMatch:
    """Returned when the failure threshold is exceeded for a source IP.

    Descriptive metadata (rule_id/name/severity/risk/mitre) is sourced from
    engine_meta/ssh_bruteforce_threshold.yaml; the literals here are fallbacks.
    severity/risk_score are the BASE values — evaluate() overrides them per alert.
    """
    rule_id: str = field(default_factory=lambda: _META.get("rule_id", "linux_t1110_ssh_bruteforce"))
    rule_name: str = field(default_factory=lambda: _META.get("rule_name", "SSH Brute Force Authentication Failures"))
    severity: str = field(default_factory=lambda: _META.get("severity", "medium"))
    risk_score: int = field(default_factory=lambda: int(_META.get("risk_score", 45)))
    mitre_tactic: str = field(default_factory=lambda: mitre_id(_META, "tactic", "TA0006"))
    mitre_technique: str = field(default_factory=lambda: mitre_id(_META, "technique", "T1110"))
    agent_id: str = ""
    source_ip: str = ""
    user_name: Optional[str] = None
    failure_count: int = 0
    threshold: int = SSH_BF_THRESHOLD
    time_window_seconds: int = SSH_BF_WINDOW_SECONDS
    dedup_seconds: int = SSH_BF_DEDUP_SECONDS
    match_reasons: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rolling failure buffer (singleton)
# ---------------------------------------------------------------------------

class SSHFailureBuffer:
    """
    Thread-safe per-(agent_id, source_ip) rolling buffer of SSH failure events.

    Entries older than ttl_seconds are lazily expired on each push/read.
    """

    def __init__(self, ttl_seconds: int = SSH_BF_WINDOW_SECONDS * 2) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        # (agent_id, source_ip) -> deque[SSHFailureEvent]
        self._store: Dict[tuple, deque] = defaultdict(deque)

    def push(self, event: SSHFailureEvent) -> None:
        key = (event.agent_id, event.source_ip)
        with self._lock:
            bucket = self._store[key]
            self._expire(bucket, event.timestamp)
            bucket.append(event)

    def get_recent(
        self, agent_id: str, source_ip: str, window_seconds: int
    ) -> List[SSHFailureEvent]:
        key = (agent_id, source_ip)
        now = time.time()
        with self._lock:
            bucket = self._store.get(key)
            if not bucket:
                return []
            self._expire(bucket, now)
            return [e for e in bucket if now - e.timestamp <= window_seconds]

    def _expire(self, bucket: deque, now: float) -> None:
        cutoff = now - self._ttl
        while bucket and bucket[0].timestamp < cutoff:
            bucket.popleft()


# ---------------------------------------------------------------------------
# Deduplication cache (singleton)
# ---------------------------------------------------------------------------

class SSHBFDedupCache:
    """
    Cooldown cache keyed by (agent_id, source_ip) to prevent alert flooding
    after the threshold is crossed.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: Dict[tuple, float] = {}

    def is_duped(self, agent_id: str, source_ip: str, cooldown_seconds: int) -> bool:
        key = (agent_id, source_ip)
        with self._lock:
            last = self._cache.get(key)
            return last is not None and (time.time() - last) < cooldown_seconds

    def mark(self, agent_id: str, source_ip: str) -> None:
        key = (agent_id, source_ip)
        with self._lock:
            self._cache[key] = time.time()
            # Lazy prune to bound growth
            if len(self._cache) > 1000:
                cutoff = time.time() - SSH_BF_DEDUP_SECONDS
                stale = [k for k, v in self._cache.items() if v < cutoff]
                for k in stale:
                    del self._cache[k]


# Module-level singletons — shared by all FastAPI background tasks in process
_GLOBAL_SSH_BUFFER: Optional[SSHFailureBuffer] = None
_SSH_BUFFER_LOCK = threading.Lock()

_GLOBAL_SSH_DEDUP: Optional[SSHBFDedupCache] = None
_SSH_DEDUP_LOCK = threading.Lock()


def get_ssh_failure_buffer() -> SSHFailureBuffer:
    global _GLOBAL_SSH_BUFFER
    if _GLOBAL_SSH_BUFFER is None:
        with _SSH_BUFFER_LOCK:
            if _GLOBAL_SSH_BUFFER is None:
                _GLOBAL_SSH_BUFFER = SSHFailureBuffer()
    return _GLOBAL_SSH_BUFFER


def get_ssh_bf_dedup() -> SSHBFDedupCache:
    global _GLOBAL_SSH_DEDUP
    if _GLOBAL_SSH_DEDUP is None:
        with _SSH_DEDUP_LOCK:
            if _GLOBAL_SSH_DEDUP is None:
                _GLOBAL_SSH_DEDUP = SSHBFDedupCache()
    return _GLOBAL_SSH_DEDUP


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SSHBruteForceEngine:
    """
    Stateless evaluator that uses the shared SSHFailureBuffer to detect
    repeated SSH authentication failures from a single source IP.
    """

    def __init__(
        self,
        buffer: Optional[SSHFailureBuffer] = None,
        dedup: Optional[SSHBFDedupCache] = None,
        threshold: int = SSH_BF_THRESHOLD,
        window_seconds: int = SSH_BF_WINDOW_SECONDS,
        dedup_seconds: int = SSH_BF_DEDUP_SECONDS,
        db: Any = None,
    ) -> None:
        self._buffer = buffer or get_ssh_failure_buffer()
        self._dedup = dedup or get_ssh_bf_dedup()
        self._threshold = threshold
        self._window = window_seconds
        self._dedup_seconds = dedup_seconds
        # Optional DB session. When present, persisted logs are the source of
        # truth for the failure count/window so it survives restarts and is not
        # limited to this worker's in-memory buffer. Falls back to the buffer on
        # any DB error.
        self._db = db

    def _recent_failures_db(
        self, agent_id: str, source_ip: str
    ) -> Optional[Tuple[int, List[str]]]:
        """Count failed SSH auth logs for (agent, source_ip) within the window.

        Returns (count, distinct_usernames) or None on any error (caller then
        falls back to the in-memory buffer).
        """
        if self._db is None:
            return None
        try:
            from sqlalchemy import or_
            from ... import models

            cutoff = datetime.utcnow() - timedelta(seconds=self._window)
            like_ip = f"%{source_ip}%"
            rows = (
                self._db.query(models.Log)
                .filter(
                    models.Log.agent_id == agent_id,
                    models.Log.timestamp >= cutoff,
                    models.Log.message.ilike(like_ip),
                    or_(
                        models.Log.message.ilike("%failed password%"),
                        models.Log.message.ilike("%authentication failure%"),
                    ),
                )
                .order_by(models.Log.timestamp.desc())
                .limit(SSH_BF_DB_ROW_LIMIT)
                .all()
            )
            users: List[str] = []
            for row in rows:
                m = _SSH_USER_RE.search(row.message or "")
                if m:
                    users.append(m.group(1))
            return len(rows), users
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(f"[SSH_BF] DB count failed, using in-memory buffer: {exc}")
            return None

    def evaluate(self, event: Dict[str, Any]) -> Optional[SSHBruteForceMatch]:
        """
        Push the event to the buffer if it is a failed SSH auth, then check
        whether the failure count for this source IP has crossed the threshold.
        Returns a SSHBruteForceMatch if an alert should be raised, else None.
        """
        event_block = event.get("event") or {}
        service_block = event.get("service") or {}

        if event_block.get("outcome") != "failure":
            return None
        if event_block.get("category") != "authentication":
            return None
        if service_block.get("name") != "ssh":
            return None

        source_ip = (event.get("source") or {}).get("ip")
        if not source_ip:
            return None

        agent_id = event.get("agent_id", "")
        user_name = (event.get("user") or {}).get("name") or None

        failure = SSHFailureEvent(
            timestamp=time.time(),
            agent_id=agent_id,
            source_ip=source_ip,
            user_name=user_name,
        )
        self._buffer.push(failure)

        # DB is authoritative when available (survives restarts, not per-worker);
        # otherwise use the in-memory buffer.
        db_result = self._recent_failures_db(agent_id, source_ip)
        if db_result is not None:
            count, users = db_result
        else:
            recent = self._buffer.get_recent(agent_id, source_ip, self._window)
            count = len(recent)
            users = [e.user_name for e in recent if e.user_name]

        if count < self._threshold:
            logger.debug(
                f"[SSH_BF] {count}/{self._threshold} failures from {source_ip} "
                f"on agent={agent_id} — below threshold"
            )
            return None

        if self._dedup.is_duped(agent_id, source_ip, self._dedup_seconds):
            logger.debug(
                f"[SSH_BF] Dedup: skipping alert for {source_ip} on agent={agent_id}"
            )
            return None

        self._dedup.mark(agent_id, source_ip)

        # Determine severity / risk based on how far over threshold we are
        if count >= self._threshold * SSH_BF_SEVERE_MULTIPLIER:
            risk_score, severity = SSH_BF_RISK_SEVERE, "high"
        elif count >= self._threshold * SSH_BF_ELEVATED_MULTIPLIER:
            risk_score, severity = SSH_BF_RISK_ELEVATED, "medium"
        else:
            risk_score, severity = SSH_BF_RISK_BASE, "medium"

        distinct_users = sorted({u for u in users if u})

        match_reasons = [
            f"{count} failed SSH authentication(s) from {source_ip} within {self._window}s",
            f"Threshold: {self._threshold} failures / {self._window}s",
        ]

        # Password spraying: many distinct usernames from one source.
        if len(distinct_users) >= SSH_BF_SPRAY_USER_THRESHOLD:
            risk_score = min(100, risk_score + SSH_BF_SPRAY_RISK_BONUS)
            if risk_score >= SSH_BF_RISK_ELEVATED + 1:
                severity = "high"
            match_reasons.append(
                f"Password spraying pattern: {len(distinct_users)} distinct usernames targeted"
            )

        user_display: Optional[str] = None
        if len(distinct_users) == 1:
            user_display = distinct_users[0]
        elif distinct_users:
            user_display = ", ".join(distinct_users)
        if user_display:
            match_reasons.append(f"Targeted user(s): {user_display}")

        logger.info(
            f"[SSH_BF] THRESHOLD EXCEEDED: agent={agent_id} source_ip={source_ip} "
            f"count={count} risk={risk_score}"
        )

        return SSHBruteForceMatch(
            agent_id=agent_id,
            source_ip=source_ip,
            user_name=user_display,
            failure_count=count,
            threshold=self._threshold,
            time_window_seconds=self._window,
            dedup_seconds=self._dedup_seconds,
            match_reasons=match_reasons,
            risk_score=risk_score,
            severity=severity,
        )
