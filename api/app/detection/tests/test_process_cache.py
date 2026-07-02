"""
test_process_cache.py — best-effort parent-process name resolution.
"""
import time

from app.detection.engine.process_cache import (
    ProcessNameCache,
    enrich_parent_name,
)


def test_record_and_lookup():
    cache = ProcessNameCache()
    cache.record("agent-1", 100, "bash")
    assert cache.lookup("agent-1", 100) == "bash"


def test_lookup_miss_returns_none():
    cache = ProcessNameCache()
    assert cache.lookup("agent-1", 999) is None


def test_per_agent_isolation():
    cache = ProcessNameCache()
    cache.record("agent-1", 100, "bash")
    assert cache.lookup("agent-2", 100) is None


def test_ttl_expiry():
    cache = ProcessNameCache(ttl_seconds=0.01)
    cache.record("agent-1", 100, "bash")
    time.sleep(0.02)
    assert cache.lookup("agent-1", 100) is None


def test_eviction_cap_enforced():
    cache = ProcessNameCache(ttl_seconds=1000, max_entries=8)
    for pid in range(20):
        cache.record("agent-1", pid, f"proc{pid}")
    # Never exceeds the cap.
    assert len(cache._store) <= 8


def test_record_ignores_bad_input():
    cache = ProcessNameCache()
    cache.record("", 100, "bash")
    cache.record("agent-1", None, "bash")
    cache.record("agent-1", 100, None)
    assert len(cache._store) == 0


def test_enrich_fills_parent_name_from_prior_child():
    # Reset the module singleton state by using enrich against a fresh event
    # that first records the parent (pid 100 -> systemd), then a child whose
    # ppid is 100.
    parent_event = {"agent_id": "a-enrich", "pid": 100, "process": {"name": "systemd"}}
    enrich_parent_name(parent_event)

    child_event = {
        "agent_id": "a-enrich",
        "pid": 200,
        "process": {"name": "bash", "parent": {"pid": 100}},
    }
    enrich_parent_name(child_event)
    assert child_event["process"]["parent"]["name"] == "systemd"


def test_enrich_never_overwrites_existing_parent_name():
    event = {
        "agent_id": "a-x",
        "process": {"name": "bash", "parent": {"pid": 1, "name": "already-set"}},
    }
    enrich_parent_name(event)
    assert event["process"]["parent"]["name"] == "already-set"


def test_enrich_safe_on_malformed_event():
    assert enrich_parent_name({}) == {}
    assert enrich_parent_name({"process": "nope"}) == {"process": "nope"}
