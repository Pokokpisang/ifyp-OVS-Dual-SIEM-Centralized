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
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

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
    """Returned when the failure threshold is exceeded for a source IP."""
    rule_id: str = "linux_t1110_ssh_bruteforce"
    rule_name: str = "SSH Brute Force Authentication Failures"
    severity: str = "medium"
    risk_score: int = 45
    mitre_tactic: str = "TA0006"
    mitre_technique: str = "T1110"
    agent_id: str = ""
    source_ip: str = ""
    user_name: Optional[str] = None
    failure_count: int = 0
    time_window_seconds: int = SSH_BF_WINDOW_SECONDS
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
    ) -> None:
        self._buffer = buffer or get_ssh_failure_buffer()
        self._dedup = dedup or get_ssh_bf_dedup()
        self._threshold = threshold
        self._window = window_seconds
        self._dedup_seconds = dedup_seconds

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

        recent = self._buffer.get_recent(agent_id, source_ip, self._window)
        count = len(recent)

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
        if count >= self._threshold * 3:
            risk_score, severity = 75, "high"
        elif count >= self._threshold * 2:
            risk_score, severity = 60, "medium"
        else:
            risk_score, severity = 45, "medium"

        # Collect unique targeted usernames within the window
        users = list({e.user_name for e in recent if e.user_name})
        user_display: Optional[str] = None
        if len(users) == 1:
            user_display = users[0]
        elif users:
            user_display = ", ".join(sorted(users))

        match_reasons = [
            f"{count} failed SSH authentication(s) from {source_ip} within {self._window}s",
            f"Threshold: {self._threshold} failures / {self._window}s",
        ]
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
            time_window_seconds=self._window,
            match_reasons=match_reasons,
            risk_score=risk_score,
            severity=severity,
        )
