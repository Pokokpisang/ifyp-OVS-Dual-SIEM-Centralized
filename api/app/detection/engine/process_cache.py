"""
Process-name cache for best-effort parent-process resolution.

auditd SYSCALL records carry a numeric ``ppid`` but not the parent's process
name, so rules and suppressions that key on ``process.parent.name`` never match
on real events. This cache records ``(agent_id, pid) -> process.name`` as exec
events stream through detection, then lets the parser fill in a parent name from
a prior child's record.

It is best-effort by design: a parent that started before the agent (or before
this worker process) is unknown, in which case ``process.parent.name`` is simply
left absent — exactly the pre-existing behaviour. State is per-process and lost
on restart; that is acceptable because a miss only reverts to the prior
(field-absent) behaviour.
"""
import threading
import time
from typing import Dict, Optional, Tuple

DEFAULT_TTL_SECONDS = 600.0
DEFAULT_MAX_ENTRIES = 5000


class ProcessNameCache:
    """Thread-safe TTL map of (agent_id, pid) -> process name."""

    def __init__(
        self,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._lock = threading.Lock()
        # (agent_id, pid) -> (name, inserted_at)
        self._store: Dict[Tuple[str, int], Tuple[str, float]] = {}

    def record(self, agent_id: str, pid: Optional[int], name: Optional[str]) -> None:
        if not agent_id or pid is None or not name:
            return
        try:
            key = (agent_id, int(pid))
        except (TypeError, ValueError):
            return
        with self._lock:
            if len(self._store) >= self._max:
                self._evict_locked()
            self._store[key] = (name, time.time())

    def lookup(self, agent_id: str, pid: Optional[int]) -> Optional[str]:
        if not agent_id or pid is None:
            return None
        try:
            key = (agent_id, int(pid))
        except (TypeError, ValueError):
            return None
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            name, inserted_at = entry
            if time.time() - inserted_at > self._ttl:
                self._store.pop(key, None)
                return None
            return name

    def _evict_locked(self) -> None:
        """Drop expired entries; if still full, drop the oldest quarter."""
        now = time.time()
        expired = [k for k, (_, ts) in self._store.items() if now - ts > self._ttl]
        for k in expired:
            self._store.pop(k, None)
        if len(self._store) < self._max:
            return
        oldest = sorted(self._store.items(), key=lambda kv: kv[1][1])
        for k, _ in oldest[: max(1, self._max // 4)]:
            self._store.pop(k, None)


# Module-level singleton — shared by all detection background tasks in-process.
_GLOBAL_CACHE: Optional[ProcessNameCache] = None
_CACHE_LOCK = threading.Lock()


def get_process_name_cache() -> ProcessNameCache:
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is None:
        with _CACHE_LOCK:
            if _GLOBAL_CACHE is None:
                _GLOBAL_CACHE = ProcessNameCache()
    return _GLOBAL_CACHE


def enrich_parent_name(event: dict) -> dict:
    """Record this event's pid→name, then fill process.parent.name from cache.

    Never overwrites an existing parent name; on a miss the field stays absent.
    Safe on malformed events. Returns the same event.
    """
    process = event.get("process")
    if not isinstance(process, dict):
        return event

    agent_id = str(event.get("agent_id") or "")
    if not agent_id:
        return event

    cache = get_process_name_cache()

    pid = event.get("pid") or process.get("pid")
    name = process.get("name")
    cache.record(agent_id, pid, name)

    parent = process.get("parent")
    if not isinstance(parent, dict):
        return event
    if parent.get("name"):
        return event  # never overwrite

    parent_pid = parent.get("pid")
    resolved = cache.lookup(agent_id, parent_pid)
    if resolved:
        parent["name"] = resolved

    return event
