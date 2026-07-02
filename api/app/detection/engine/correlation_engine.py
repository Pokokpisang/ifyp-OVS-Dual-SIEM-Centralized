"""
Lightweight in-memory correlation engine for detecting multi-event attack patterns.

Handles the real auditd fragmentation case where:
  Event A: curl / wget with a remote URL  (EXECVE record for curl)
  Event B: bash / sh / dash / zsh         (EXECVE record for the piped shell)

appear as two separate events within a short time window.

Feature flags (env vars):
  ENABLE_CORRELATION_ENGINE       default: "true"
  CORRELATION_WINDOW_SECONDS      default: 10
  CORRELATION_BUFFER_TTL_SECONDS  default: 60
  CORRELATION_DEDUP_SECONDS       default: 60
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .engine_metadata import load_engine_metadata, mitre_id

logger = logging.getLogger("detection.correlation_engine")

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

ENABLE_CORRELATION_ENGINE: bool = _env_bool("ENABLE_CORRELATION_ENGINE", True)
CORRELATION_WINDOW_SECONDS: int = _env_int("CORRELATION_WINDOW_SECONDS", 10)
CORRELATION_BUFFER_TTL_SECONDS: int = _env_int("CORRELATION_BUFFER_TTL_SECONDS", 60)
CORRELATION_DEDUP_SECONDS: int = _env_int("CORRELATION_DEDUP_SECONDS", 60)

# Descriptive alert metadata is defined in engine_meta/ (detection-as-code); the
# hardcoded literals below are only fallbacks if the YAML is missing/corrupt.
_META = load_engine_metadata("correlation_download_execution")

# ---------------------------------------------------------------------------
# Event A / B criteria
# ---------------------------------------------------------------------------

# Process names that are considered network download tools (Event A)
_DOWNLOAD_TOOLS: frozenset = frozenset({"curl", "wget", "nc", "ncat", "socat", "openssl"})

# Shell-related indicators in the command line that elevate Event A significance
# (the download is fetching something shell-related)
_SHELL_INDICATORS: Tuple[str, ...] = (
    ".sh",
    "bash",
    "/bin/sh",
    "/bin/bash",
    "sh ",
    "| sh",
    "| bash",
)

# Process names that constitute Event B (shell execution)
_SHELL_PROCESSES: frozenset = frozenset({"bash", "sh", "dash", "zsh"})

# Optional supporting evidence process names (recorded in metadata but NOT primary triggers)
_SHELL_EVIDENCE_PROCESSES: frozenset = frozenset({"whoami", "hostname"})

# Command-line patterns that also qualify as Event B even when process.name is generic
_SHELL_CMD_INDICATORS: Tuple[str, ...] = (
    "bash -c",
    "sh -c",
    "/bin/bash",
    "/bin/sh",
    ".sh",
)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BufferedProcessEvent:
    """A normalised snapshot of a process event stored in the rolling buffer."""
    agent_id: str
    timestamp: float                          # UNIX epoch seconds (time.time())
    process_name: str                         # process.name
    command_line: str                         # process.command_line
    user_name: Optional[str] = None          # user.name  (optional corr key)
    tty: Optional[str] = None                # tty        (optional corr key)
    session_id: Optional[str] = None         # ses        (optional corr key)
    cwd: Optional[str] = None                # cwd        (optional corr key)


@dataclass
class CorrelationMatch:
    """Returned when a correlation pattern is detected.

    Descriptive metadata (rule_id/name/severity/risk/mitre) is sourced from
    engine_meta/correlation_download_execution.yaml; the literals here are
    fallbacks only.
    """
    rule_id: str = field(default_factory=lambda: _META.get("rule_id", "linux_t1059_download_then_shell_execution"))
    rule_name: str = field(default_factory=lambda: _META.get("rule_name", "Network Script Download Followed by Shell Execution"))
    severity: str = field(default_factory=lambda: _META.get("severity", "high"))
    risk_score: int = field(default_factory=lambda: int(_META.get("risk_score", 70)))
    mitre_tactic: str = field(default_factory=lambda: mitre_id(_META, "tactic", "TA0002"))
    mitre_technique: str = field(default_factory=lambda: mitre_id(_META, "technique", "T1059.004"))
    agent_id: str = ""
    first_event_process: str = ""
    first_event_command: str = ""
    second_event_process: str = ""
    second_event_command: str = ""
    time_delta_seconds: float = 0.0
    correlation_window_seconds: int = CORRELATION_WINDOW_SECONDS
    reason: str = ""
    source_url: str = ""                      # URL extracted from Event A (for dedup)
    supporting_evidence: List[Dict[str, str]] = field(default_factory=list)
    optional_keys: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rolling buffer (singleton)
# ---------------------------------------------------------------------------

class ProcessEventBuffer:
    """
    Thread-safe, per-agent_id rolling buffer of recent process events.

    Entries older than CORRELATION_BUFFER_TTL_SECONDS are lazily expired
    whenever a new event arrives for that agent, so no background thread
    is required.
    """

    def __init__(
        self,
        ttl_seconds: int = CORRELATION_BUFFER_TTL_SECONDS,
        max_entries_per_agent: int = 200,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries_per_agent
        self._lock = threading.Lock()
        # agent_id -> deque[BufferedProcessEvent]
        self._store: Dict[str, deque] = defaultdict(deque)

    # ------------------------------------------------------------------
    def push(self, event: BufferedProcessEvent) -> None:
        with self._lock:
            bucket = self._store[event.agent_id]
            self._expire(bucket)
            bucket.append(event)
            # Enforce max size (drop oldest)
            while len(bucket) > self._max:
                bucket.popleft()

    # ------------------------------------------------------------------
    def get_recent(self, agent_id: str) -> List[BufferedProcessEvent]:
        """Return all non-expired events for *agent_id* (oldest first)."""
        with self._lock:
            bucket = self._store.get(agent_id)
            if not bucket:
                return []
            self._expire(bucket)
            return list(bucket)

    # ------------------------------------------------------------------
    def _expire(self, bucket: deque) -> None:
        cutoff = time.time() - self._ttl
        while bucket and bucket[0].timestamp < cutoff:
            bucket.popleft()


# Module-level singleton — shared by all FastAPI background tasks in process
_GLOBAL_BUFFER: Optional[ProcessEventBuffer] = None
_BUFFER_LOCK = threading.Lock()


def get_process_event_buffer() -> ProcessEventBuffer:
    global _GLOBAL_BUFFER
    if _GLOBAL_BUFFER is None:
        with _BUFFER_LOCK:
            if _GLOBAL_BUFFER is None:
                _GLOBAL_BUFFER = ProcessEventBuffer()
    return _GLOBAL_BUFFER


# ---------------------------------------------------------------------------
# Deduplication cache
# ---------------------------------------------------------------------------

class DedupCache:
    """
    In-memory cooldown cache keyed by (agent_id, rule_id, source_url).
    Prevents duplicate correlation alerts within CORRELATION_DEDUP_SECONDS.
    """

    def __init__(self, ttl_seconds: int = CORRELATION_DEDUP_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        # key -> last_fire_time (UNIX epoch)
        self._cache: Dict[str, float] = {}

    def is_duplicate(self, agent_id: str, rule_id: str, source_url: str) -> bool:
        key = f"{agent_id}|{rule_id}|{source_url}"
        with self._lock:
            last = self._cache.get(key)
            if last and (time.time() - last) < self._ttl:
                return True
            return False

    def mark(self, agent_id: str, rule_id: str, source_url: str) -> None:
        key = f"{agent_id}|{rule_id}|{source_url}"
        with self._lock:
            self._cache[key] = time.time()
            # Lazy prune: remove stale entries to avoid unbounded growth
            if len(self._cache) > 1000:
                cutoff = time.time() - self._ttl
                stale = [k for k, v in self._cache.items() if v < cutoff]
                for k in stale:
                    del self._cache[k]


_GLOBAL_DEDUP: Optional[DedupCache] = None
_DEDUP_LOCK = threading.Lock()


def get_dedup_cache() -> DedupCache:
    global _GLOBAL_DEDUP
    if _GLOBAL_DEDUP is None:
        with _DEDUP_LOCK:
            if _GLOBAL_DEDUP is None:
                _GLOBAL_DEDUP = DedupCache()
    return _GLOBAL_DEDUP


# ---------------------------------------------------------------------------
# Helper: event field extraction
# ---------------------------------------------------------------------------

def _get(event: Dict[str, Any], *path: str) -> str:
    """Safely traverse nested dict with dot-path, returning '' if missing."""
    cur: Any = event
    for key in path:
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(key, "")
    return str(cur) if cur else ""


# Bare IP-based URL pattern (no scheme): matches 1.2.3.4/path or 1.2.3.4:port/path
# Intentionally requires a path component (/) to avoid matching plain IPs.
_BARE_IP_URL_RE = re.compile(
    r'\b(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/\S*)'
)


def _extract_url(cmd: str) -> str:
    """Extract the first URL (http(s):// or bare IP:port/path) from a command line string."""
    for token in cmd.split():
        if token.startswith("http://") or token.startswith("https://"):
            return token
    m = _BARE_IP_URL_RE.search(cmd)
    if m:
        return m.group(1)
    return ""


def _is_event_a(process_name: str, command_line: str) -> Tuple[bool, str]:
    """
    Returns (True, url) if the event matches download-tool + remote URL criteria.

    Shell-related indicators in the command are not required: the two-event
    pattern (download tool + URL, then shell execution within the correlation
    window) is sufficient evidence on its own.  False positives are handled
    by the existing suppression engine.

    Accepts both scheme-prefixed URLs (http://, https://) and bare IP-based
    URLs (e.g. 192.168.1.1:8080/script.sh) since curl/wget default to HTTP
    when no scheme is supplied.
    """
    name_lower = process_name.lower()
    if name_lower not in _DOWNLOAD_TOOLS:
        return False, ""

    cmd_lower = command_line.lower()

    if "http://" in cmd_lower or "https://" in cmd_lower:
        url = _extract_url(command_line)
        return True, url

    # Also accept bare IP-based URLs (attacker omits http:// scheme)
    if _BARE_IP_URL_RE.search(command_line):
        url = _extract_url(command_line)
        return True, url

    return False, ""


def _is_event_b(process_name: str, command_line: str) -> bool:
    """
    Returns True if the event is a primary shell execution (Event B).
    Restricted to core shell processes only.
    """
    name_lower = process_name.lower()
    if name_lower in _DOWNLOAD_TOOLS:
        return False

    if name_lower in _SHELL_PROCESSES:
        return True

    # Also accept when command line contains shell invocation patterns
    # (handles cases where process.name is set to the script name)
    cmd_lower = command_line.lower()
    if any(ind in cmd_lower for ind in _SHELL_CMD_INDICATORS):
        return True

    return False


def _optional_keys(event: Dict[str, Any]) -> Dict[str, str]:
    """Extract optional correlation keys from an event."""
    keys: Dict[str, str] = {}
    user = _get(event, "user", "name") or _get(event, "username")
    if user:
        keys["user_name"] = user
    tty = _get(event, "tty") or _get(event, "terminal")
    if tty:
        keys["tty"] = tty
    ses = str(event.get("ses", "")) or _get(event, "session_id")
    if ses:
        keys["session_id"] = ses
    cwd = _get(event, "cwd")
    if cwd:
        keys["cwd"] = cwd
    return keys


def _keys_match(a: BufferedProcessEvent, b_keys: Dict[str, str]) -> bool:
    """
    Returns True if all optional keys present on *both* sides match.
    If a key is absent from either side, it is ignored (not a mismatch).
    """
    pairs = [
        ("user_name",  a.user_name,   b_keys.get("user_name")),
        ("tty",        a.tty,         b_keys.get("tty")),
        ("session_id", a.session_id,  b_keys.get("session_id")),
        ("cwd",        a.cwd,         b_keys.get("cwd")),
    ]
    for name, av, bv in pairs:
        if av and bv and av != bv:
            logger.debug(f"[CORR] Optional key mismatch on '{name}': {av!r} vs {bv!r}")
            return False
    return True


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Stateless evaluator that uses the shared ProcessEventBuffer to detect
    the download-then-shell pattern.

    Order-insensitive:
    - If current event is B (shell), scan recent for A (download).
    - If current event is A (download), scan recent for B (shell).
    """

    def __init__(
        self,
        buffer: ProcessEventBuffer,
        dedup: DedupCache,
        window_seconds: int = CORRELATION_WINDOW_SECONDS,
    ) -> None:
        self._buffer = buffer
        self._dedup = dedup
        self._window = window_seconds
        logger.info(f"[CORRELATION] Engine initialized. enabled={ENABLE_CORRELATION_ENGINE} window={self._window}s")

    # ------------------------------------------------------------------
    def evaluate(self, event: Dict[str, Any]) -> Optional[CorrelationMatch]:
        """
        1. Extract process fields from the normalised event.
        2. Push a buffered snapshot.
        3. Determine if current event is A or B.
        4. Scan buffer for the opposite event from same agent within window.
        """
        agent_id = event.get("agent_id", "")
        if not agent_id:
            return None

        process_name = _get(event, "process", "name")
        command_line  = _get(event, "process", "command_line")

        if not process_name:
            return None

        logger.debug(f"[CORRELATION] Received event: agent={agent_id} proc={process_name} cmd={command_line[:100]}...")

        opt_keys = _optional_keys(event)

        # --- Push this event to the buffer ---
        buffered = BufferedProcessEvent(
            agent_id=agent_id,
            timestamp=time.time(),
            process_name=process_name,
            command_line=command_line,
            user_name=opt_keys.get("user_name"),
            tty=opt_keys.get("tty"),
            session_id=opt_keys.get("session_id"),
            cwd=opt_keys.get("cwd"),
        )
        self._buffer.push(buffered)

        # --- Classification ---
        is_a, url = _is_event_a(process_name, command_line)
        is_b = _is_event_b(process_name, command_line)

        if not is_a and not is_b:
            logger.debug(f"[CORRELATION] Classified type=NONE for proc={process_name}")
            return None

        event_type = "A" if is_a else "B"
        logger.info(f"[CORRELATION] Classified type={event_type} for proc={process_name} agent={agent_id}")

        # --- Scan buffer for a preceding matching opposite event ---
        now = time.time()
        recent_events = self._buffer.get_recent(agent_id)
        logger.debug(f"[CORRELATION] Buffer size for agent={agent_id}: {len(recent_events)}")
        for candidate in reversed(recent_events):
            if candidate is buffered:
                continue

            delta = abs(now - candidate.timestamp)
            logger.debug(f"[CORRELATION] Checking candidate: proc={candidate.process_name} delta={delta:.2f}s")
            
            if delta > self._window:
                continue

            # If current is B, look for A. If current is A, look for B.
            match_found = False
            ev_a = None
            ev_b = None
            found_url = ""

            if is_b:
                cand_is_a, cand_url = _is_event_a(candidate.process_name, candidate.command_line)
                if cand_is_a:
                    logger.debug(f"[CORRELATION] Found matching Event A in buffer: {candidate.process_name}")
                    match_found = True
                    ev_a = candidate
                    ev_b = buffered
                    found_url = cand_url
            elif is_a:
                if _is_event_b(candidate.process_name, candidate.command_line):
                    logger.debug(f"[CORRELATION] Found matching Event B in buffer: {candidate.process_name}")
                    match_found = True
                    ev_a = buffered
                    ev_b = candidate
                    found_url = url # url of current Event A

            if not match_found:
                continue

            # Optional key match
            if not _keys_match(candidate, opt_keys):
                logger.debug(f"[CORRELATION] Skipped match due to key mismatch between current and {candidate.process_name}")
                continue

            # --- Dedup check ---
            rule_id = "linux_t1059_download_then_shell_execution"
            if self._dedup.is_duplicate(agent_id, rule_id, found_url):
                logger.info(f"[CORRELATION] Duplicate suppressed: agent={agent_id} url={found_url}")
                return None

            # --- Build match ---
            # Collect any supporting evidence from the buffer within the window
            supporting_evidence = []
            for ev in recent_events:
                if abs(now - ev.timestamp) <= self._window:
                    if ev.process_name.lower() in _SHELL_EVIDENCE_PROCESSES:
                        supporting_evidence.append({
                            "process": ev.process_name,
                            "command": ev.command_line,
                            "delta": f"{abs(now - ev.timestamp):.2f}s"
                        })

            reason = (
                f"Network script download ({ev_a.process_name}) followed by shell execution "
                f"({ev_b.process_name}) on the same agent within {self._window} seconds. "
                f"URL: {found_url or 'unknown'}"
            )

            match = CorrelationMatch(
                agent_id=agent_id,
                first_event_process=ev_a.process_name,
                first_event_command=ev_a.command_line,
                second_event_process=ev_b.process_name,
                second_event_command=ev_b.command_line,
                time_delta_seconds=round(delta, 2),
                correlation_window_seconds=self._window,
                reason=reason,
                source_url=found_url,
                supporting_evidence=supporting_evidence,
                optional_keys=opt_keys,
            )

            self._dedup.mark(agent_id, rule_id, found_url)
            logger.info(f"[CORRELATION] MATCH FOUND: agent={agent_id} A={ev_a.process_name} B={ev_b.process_name} delta={delta:.2f}s")
            return match

        return None
