"""
Tests for AuditEventAggregator.

Unit tests use AuditEventAggregator() directly (no singleton) so each test
starts with an empty buffer — same isolation pattern as other detection tests.

The integration test at the bottom simulates the full pipeline:
    raw auditd EXECVE record + raw auditd PATH record
    → AuditdParser.normalize_log()
    → AuditEventAggregator.add_record()
    → flush_all()
    → YAMLDetectionEngine.evaluate_event()
    → T1543.002 rule matches
"""
import time

import pytest

from app.detection.engine.audit_event_aggregator import AuditEventAggregator
from app.detection.engine.audit_parser import AuditdParser
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

AUDIT_ID = "1710000000.123:456"
AGENT_ID = "test-agent-001"


def _msg(record_type: str, audit_id: str = AUDIT_ID, extra: str = "") -> str:
    return f"type={record_type} msg=audit({audit_id}): {extra}"


# ---------------------------------------------------------------------------
# 1. extract_audit_event_id
# ---------------------------------------------------------------------------


def test_extract_audit_event_id_valid():
    agg = AuditEventAggregator()
    msg = f"type=SYSCALL msg=audit({AUDIT_ID}): pid=1234 uid=0"
    assert agg.extract_audit_event_id(msg) == AUDIT_ID


def test_extract_audit_event_id_missing():
    agg = AuditEventAggregator()
    assert agg.extract_audit_event_id("type=SSHD msg=something else") is None
    assert agg.extract_audit_event_id("") is None
    assert agg.extract_audit_event_id("no audit id here") is None


# ---------------------------------------------------------------------------
# 2. Grouping behaviour
# ---------------------------------------------------------------------------


def test_group_same_audit_event_id():
    agg = AuditEventAggregator(ttl_seconds=60)
    rec_a = {"message": _msg("SYSCALL"), "agent_id": AGENT_ID, "process": {"name": "bash"}}
    rec_b = {"message": _msg("EXECVE"), "agent_id": AGENT_ID, "process": {"command_line": "bash -c id"}}

    agg.add_record(AGENT_ID, AUDIT_ID, rec_a)
    agg.add_record(AGENT_ID, AUDIT_ID, rec_b)

    completed = agg.flush_all()
    assert len(completed) == 1
    merged = completed[0]
    assert merged["process"]["name"] == "bash"
    assert merged["process"]["command_line"] == "bash -c id"


def test_not_merge_different_audit_event_ids():
    agg = AuditEventAggregator(ttl_seconds=60)
    rec_a = {"message": _msg("SYSCALL", "1710000000.100:111"), "agent_id": AGENT_ID}
    rec_b = {"message": _msg("PATH", "1710000000.200:222"), "agent_id": AGENT_ID}

    agg.add_record(AGENT_ID, "1710000000.100:111", rec_a)
    agg.add_record(AGENT_ID, "1710000000.200:222", rec_b)

    completed = agg.flush_all()
    assert len(completed) == 2


# ---------------------------------------------------------------------------
# 3. Deep merge semantics
# ---------------------------------------------------------------------------


def test_deep_merge_nested_dict():
    agg = AuditEventAggregator()
    base = {"process": {"name": "bash", "command_line": ""}, "user": {"id": "0"}}
    incoming = {
        "process": {"command_line": "bash -c whoami", "executable": "/bin/bash"},
        "file": {"path": "/etc/systemd/system/evil.service"},
    }
    merged = agg._deep_merge(base, incoming)

    # Incoming has no "name" key → existing value kept
    assert merged["process"]["name"] == "bash"
    # Base command_line was empty → incoming fills it
    assert merged["process"]["command_line"] == "bash -c whoami"
    # New key added from incoming
    assert merged["process"]["executable"] == "/bin/bash"
    assert merged["file"]["path"] == "/etc/systemd/system/evil.service"
    # Unrelated key untouched
    assert merged["user"]["id"] == "0"


def test_deep_merge_preserves_nonempty_existing_when_incoming_empty():
    """Incoming None / empty string must NOT blank out a useful existing value."""
    agg = AuditEventAggregator()
    base = {"event": {"action": "created", "category": "file"}}
    incoming = {"event": {"action": None, "category": "", "type": "change"}}
    merged = agg._deep_merge(base, incoming)

    assert merged["event"]["action"] == "created"   # kept — incoming is None
    assert merged["event"]["category"] == "file"    # kept — incoming is empty string
    assert merged["event"]["type"] == "change"      # new key added from incoming


def test_deep_merge_last_write_wins_for_nonempty_leaf():
    """
    When both base and incoming have non-empty leaf values the incoming
    (later) value must win.  This is the critical case for auditd PATH
    records: PARENT record sets file.path to the directory, then the CREATE
    record sets it to the actual file — the file path must survive.
    """
    agg = AuditEventAggregator()
    base     = {"file": {"path": "/etc/systemd/system"},
                "event": {"action": "change"}}
    incoming = {"file": {"path": "/etc/systemd/system/backdoor.service"},
                "event": {"action": "created"}}
    merged = agg._deep_merge(base, incoming)

    assert merged["file"]["path"] == "/etc/systemd/system/backdoor.service"
    assert merged["event"]["action"] == "created"


# ---------------------------------------------------------------------------
# 4. PATH + EXECVE merge produces all required T1543 fields
# ---------------------------------------------------------------------------


def test_path_execve_merge_produces_required_fields():
    agg = AuditEventAggregator(ttl_seconds=60)

    execve_record = {
        "message": _msg("EXECVE"),
        "agent_id": AGENT_ID,
        "process": {"name": "bash", "command_line": "bash -c ExecStart=/tmp/backdoor.sh"},
        "event": {},
        "file": {},
    }
    path_record = {
        "message": _msg("PATH"),
        "agent_id": AGENT_ID,
        "process": {},
        "event": {"action": "created", "category": "file", "type": "change"},
        "file": {"path": "/etc/systemd/system/backdoor.service", "name": "backdoor.service"},
    }

    agg.add_record(AGENT_ID, AUDIT_ID, execve_record)
    agg.add_record(AGENT_ID, AUDIT_ID, path_record)
    merged = agg.flush_all()[0]

    assert merged["process"]["command_line"] == "bash -c ExecStart=/tmp/backdoor.sh"
    assert merged["file"]["path"] == "/etc/systemd/system/backdoor.service"
    assert merged["event"]["action"] == "created"


# ---------------------------------------------------------------------------
# 5. Missing audit event ID — safe pass-through
# ---------------------------------------------------------------------------


def test_missing_audit_event_id_no_crash():
    agg = AuditEventAggregator()
    # extract_audit_event_id must return None without raising
    assert agg.extract_audit_event_id("") is None
    assert agg.extract_audit_event_id("type=SSHD msg=something") is None
    assert agg.extract_audit_event_id("random garbage") is None

    # flush on empty buffer must be safe
    assert agg.flush_all() == []
    assert agg.flush_expired() == []


# ---------------------------------------------------------------------------
# 6. flush_expired TTL behaviour
# ---------------------------------------------------------------------------


def test_flush_expired_returns_events(monkeypatch):
    agg = AuditEventAggregator(ttl_seconds=2.0)

    # Simulate first record arriving at t=0
    t_start = 1000.0
    monkeypatch.setattr(time, "time", lambda: t_start)

    rec = {
        "message": _msg("SYSCALL"),
        "agent_id": AGENT_ID,
        "process": {"name": "bash"},
    }
    result = agg.add_record(AGENT_ID, AUDIT_ID, rec)
    assert result == []  # not expired yet

    # Advance time past TTL
    monkeypatch.setattr(time, "time", lambda: t_start + 3.0)
    expired = agg.flush_expired()

    assert len(expired) == 1
    assert expired[0]["process"]["name"] == "bash"
    # Buffer should now be empty
    assert agg.flush_all() == []


def test_flush_expired_does_not_return_unexpired(monkeypatch):
    agg = AuditEventAggregator(ttl_seconds=10.0)

    t_start = 2000.0
    monkeypatch.setattr(time, "time", lambda: t_start)

    rec = {"message": _msg("SYSCALL"), "agent_id": AGENT_ID}
    agg.add_record(AGENT_ID, AUDIT_ID, rec)

    # Only 1 second has passed — TTL is 10 s
    monkeypatch.setattr(time, "time", lambda: t_start + 1.0)
    assert agg.flush_expired() == []


# ---------------------------------------------------------------------------
# 7. flush_all
# ---------------------------------------------------------------------------


def test_flush_all_returns_all_pending():
    agg = AuditEventAggregator(ttl_seconds=60)
    agg.add_record(AGENT_ID, "id:1", {"message": _msg("SYSCALL", "1:1"), "agent_id": AGENT_ID})
    agg.add_record(AGENT_ID, "id:2", {"message": _msg("PATH", "1:2"), "agent_id": AGENT_ID})

    completed = agg.flush_all()
    assert len(completed) == 2
    # Buffer must be empty after flush_all
    assert agg.flush_all() == []


def test_flush_all_empty_buffer():
    agg = AuditEventAggregator()
    assert agg.flush_all() == []


# ---------------------------------------------------------------------------
# 8. audit metadata is attached
# ---------------------------------------------------------------------------


def test_audit_metadata_attached():
    agg = AuditEventAggregator(ttl_seconds=60)
    rec_a = {"message": _msg("SYSCALL"), "agent_id": AGENT_ID}
    rec_b = {"message": _msg("EXECVE"), "agent_id": AGENT_ID}

    agg.add_record(AGENT_ID, AUDIT_ID, rec_a)
    agg.add_record(AGENT_ID, AUDIT_ID, rec_b)

    merged = agg.flush_all()[0]
    assert merged["audit"]["event_id"] == AUDIT_ID
    assert merged["audit"]["record_count"] == 2


# ---------------------------------------------------------------------------
# 9. Integration: EXECVE + PATH merge → T1543.002 detection
# ---------------------------------------------------------------------------


def test_t1543_detection_on_merged_auditd_event():
    """
    Full pipeline simulation with realistic auditd record ordering:

    1. SYSCALL  — process identity (arrives first)
    2. EXECVE   — command-line arguments → process.command_line
    3. PATH (PARENT)  — parent directory record that auditd always emits first
    4. PATH (CREATE)  — the actual .service file being written (arrives after PARENT)

    The deep-merge must let the CREATE record's file.path overwrite the
    PARENT record's directory path so the T1543.002 regex check can pass.
    """
    agg = AuditEventAggregator(ttl_seconds=2)

    # 1. SYSCALL — process context
    raw_syscall = {
        "message": (
            f"type=SYSCALL msg=audit({AUDIT_ID}): "
            "arch=c000003e syscall=2 success=yes pid=1234 ppid=1 uid=0 "
            "comm=bash exe=/bin/bash"
        ),
        "log_type": "auditd",
        "agent_id": AGENT_ID,
        "hostname": "prod1",
    }

    # 2. EXECVE — command line with ExecStart indicator
    raw_execve = {
        "message": (
            f"type=EXECVE msg=audit({AUDIT_ID}): "
            "a0=bash a1=-c a2=ExecStart=/tmp/backdoor.sh"
        ),
        "log_type": "auditd",
        "agent_id": AGENT_ID,
        "hostname": "prod1",
    }

    # 3. PATH PARENT — directory record (auditd always emits this first)
    raw_path_parent = {
        "message": (
            f"type=PATH msg=audit({AUDIT_ID}): "
            "item=0 name=/etc/systemd/system nametype=PARENT"
        ),
        "log_type": "auditd",
        "agent_id": AGENT_ID,
        "hostname": "prod1",
    }

    # 4. PATH CREATE — the actual .service file (arrives after PARENT)
    raw_path_create = {
        "message": (
            f"type=PATH msg=audit({AUDIT_ID}): "
            "item=1 name=/etc/systemd/system/backdoor.service nametype=CREATE"
        ),
        "log_type": "auditd",
        "agent_id": AGENT_ID,
        "hostname": "prod1",
    }

    norm_syscall      = AuditdParser.normalize_log(raw_syscall)
    norm_execve       = AuditdParser.normalize_log(raw_execve)
    norm_path_parent  = AuditdParser.normalize_log(raw_path_parent)
    norm_path_create  = AuditdParser.normalize_log(raw_path_create)

    # Sanity: EXECVE produces command_line, PARENT sets directory, CREATE sets file
    assert "ExecStart=" in norm_execve.get("process", {}).get("command_line", "")
    assert norm_path_parent.get("file", {}).get("path") == "/etc/systemd/system"
    assert norm_path_create.get("file", {}).get("path") == "/etc/systemd/system/backdoor.service"
    assert norm_path_create.get("event", {}).get("action") == "created"

    # --- Aggregate in realistic auditd order ---
    agg.add_record(AGENT_ID, AUDIT_ID, norm_syscall)
    agg.add_record(AGENT_ID, AUDIT_ID, norm_execve)
    agg.add_record(AGENT_ID, AUDIT_ID, norm_path_parent)  # sets file.path = directory
    agg.add_record(AGENT_ID, AUDIT_ID, norm_path_create)  # must overwrite with .service path
    completed = agg.flush_all()

    assert len(completed) == 1, "Expected exactly one merged event"
    merged = completed[0]

    # All three T1543.002 required fields must be present in the merged event
    assert "ExecStart=" in merged["process"]["command_line"], (
        "process.command_line missing from merged event"
    )
    assert merged["file"]["path"] == "/etc/systemd/system/backdoor.service", (
        "file.path is the PARENT directory, not the service file — "
        "CREATE PATH record did not overwrite PARENT PATH record"
    )
    assert merged["event"]["action"] == "created", (
        "event.action is not 'created' — CREATE PATH record did not overwrite PARENT"
    )

    # --- Detection ---
    engine = YAMLDetectionEngine()
    candidates = engine.evaluate_event(merged, return_unmatched=True)

    t1543 = next(
        (c for c in candidates if c.rule_id == "linux_t1543_002_systemd_service_persistence"),
        None,
    )
    assert t1543 is not None, (
        "T1543.002 rule not evaluated — check rule file exists and is enabled"
    )
    assert t1543.matched is True, (
        f"T1543.002 did not match on merged event. "
        f"missing_fields={t1543.missing_fields} match_reasons={t1543.match_reasons}"
    )
    assert not t1543.suppressed, "T1543.002 alert should not be suppressed"
