import pytest
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine
from app.detection.engine.ssh_bruteforce_engine import (
    SSHBruteForceEngine,
    SSHFailureBuffer,
    SSHBFDedupCache,
)


@pytest.fixture
def engine():
    return YAMLDetectionEngine()


def _failed_ssh_event(source_ip="192.168.1.100", user="root", agent_id="agent-001"):
    return {
        "message": f"Failed password for {user} from {source_ip} port 22 ssh2",
        "log_type": "auth",
        "hostname": "test-host",
        "agent_id": agent_id,
        "event": {"outcome": "failure", "category": "authentication"},
        "service": {"name": "ssh"},
        "source": {"ip": source_ip},
        "user": {"name": user},
        "host": {"name": "test-host"},
    }


def _success_ssh_event():
    return {
        "message": "Accepted password for admin from 192.168.1.50 port 22 ssh2",
        "log_type": "auth",
        "hostname": "test-host",
        "agent_id": "agent-001",
        "event": {"outcome": "success", "category": "authentication"},
        "service": {"name": "ssh"},
        "source": {"ip": "192.168.1.50"},
        "user": {"name": "admin"},
        "host": {"name": "test-host"},
    }


# ---------------------------------------------------------------------------
# YAML rule tests
# ---------------------------------------------------------------------------

def test_t1110_yaml_rule_matches_failed_ssh_event(engine):
    candidates = engine.evaluate_event(_failed_ssh_event())
    t1110 = next(
        (c for c in candidates if c.rule_id == "linux_t1110_ssh_bruteforce"), None
    )
    assert t1110 is not None, "Expected linux_t1110_ssh_bruteforce candidate"
    assert t1110.matched is True
    assert t1110.suppressed is False
    assert t1110.severity.lower() == "low"
    assert t1110.mitre.get("technique", {}).get("id") == "T1110"


def test_t1110_privileged_account_raises_score(engine):
    # root is a privileged account: base 35 + 5 = 40, still "low".
    root = next(
        c for c in engine.evaluate_event(_failed_ssh_event(user="root"))
        if c.rule_id == "linux_t1110_ssh_bruteforce"
    )
    assert root.risk_score == 40
    assert any("Privileged account" in r for r in root.adjustment_reasons)

    # A non-privileged account gets no bump: stays 35.
    nonpriv = next(
        c for c in engine.evaluate_event(_failed_ssh_event(user="deploybot"))
        if c.rule_id == "linux_t1110_ssh_bruteforce"
    )
    assert nonpriv.risk_score == 35


def test_t1110_yaml_rule_no_match_success_event(engine):
    candidates = engine.evaluate_event(_success_ssh_event())
    t1110 = next(
        (c for c in candidates if c.rule_id == "linux_t1110_ssh_bruteforce"), None
    )
    # Success events should not match the failure rule
    assert t1110 is None or t1110.matched is False


def test_t1110_yaml_rule_skips_missing_source_ip(engine):
    event = _failed_ssh_event()
    del event["source"]  # remove source.ip entirely

    candidates = engine.evaluate_event(event, return_unmatched=True)
    t1110 = next(
        (c for c in candidates if c.rule_id == "linux_t1110_ssh_bruteforce"), None
    )
    assert t1110 is not None
    assert t1110.matched is False
    assert "source.ip" in t1110.missing_fields


# ---------------------------------------------------------------------------
# SSHBruteForceEngine threshold tests
# ---------------------------------------------------------------------------

def _fresh_engine(threshold=5, window=60, dedup_seconds=60):
    buf = SSHFailureBuffer(ttl_seconds=window * 2)
    dedup = SSHBFDedupCache()
    return SSHBruteForceEngine(
        buffer=buf,
        dedup=dedup,
        threshold=threshold,
        window_seconds=window,
        dedup_seconds=dedup_seconds,
    )


def test_ssh_bruteforce_no_alert_before_threshold():
    bf = _fresh_engine(threshold=5)
    event = _failed_ssh_event()
    for _ in range(4):
        result = bf.evaluate(event)
        assert result is None, "Should not alert before reaching threshold"


def test_ssh_bruteforce_threshold_triggers_after_5_failures():
    bf = _fresh_engine(threshold=5)
    event = _failed_ssh_event(source_ip="10.0.0.99", agent_id="agent-002")

    result = None
    for _ in range(5):
        result = bf.evaluate(event)

    assert result is not None, "Expected SSHBruteForceMatch on 5th failure"
    assert result.rule_id == "linux_t1110_ssh_bruteforce"
    assert result.failure_count == 5
    assert result.source_ip == "10.0.0.99"
    assert result.agent_id == "agent-002"
    assert result.mitre_technique == "T1110"
    assert result.mitre_tactic == "TA0006"
    assert len(result.match_reasons) >= 1


def test_ssh_bruteforce_dedup_prevents_repeat_alert():
    bf = _fresh_engine(threshold=5, dedup_seconds=60)
    event = _failed_ssh_event(source_ip="10.0.0.88", agent_id="agent-003")

    # Trigger threshold
    match = None
    for _ in range(5):
        match = bf.evaluate(event)

    assert match is not None, "First threshold crossing should produce a match"

    # Subsequent failures within dedup window should be suppressed
    for _ in range(3):
        result = bf.evaluate(event)
        assert result is None, "Dedup should suppress repeated alerts"


def test_ssh_bruteforce_includes_user_name_in_match():
    bf = _fresh_engine(threshold=5)
    event = _failed_ssh_event(source_ip="172.16.0.1", user="administrator", agent_id="agent-004")

    match = None
    for _ in range(5):
        match = bf.evaluate(event)

    assert match is not None
    assert match.user_name == "administrator"


def test_ssh_bruteforce_no_match_for_success_event():
    bf = _fresh_engine(threshold=5)
    for _ in range(10):
        result = bf.evaluate(_success_ssh_event())
        assert result is None, "Success events must never trigger brute-force match"


def test_ssh_bruteforce_match_includes_threshold_and_dedup():
    threshold = 5
    dedup_secs = 90
    bf = _fresh_engine(threshold=threshold, dedup_seconds=dedup_secs)
    event = _failed_ssh_event(source_ip="10.0.0.77", agent_id="agent-005")

    match = None
    for _ in range(threshold):
        match = bf.evaluate(event)

    assert match is not None
    assert match.threshold == threshold, "threshold must be carried on the match"
    assert match.dedup_seconds == dedup_secs, "dedup_seconds must be carried on the match"
    assert match.time_window_seconds == 60  # default window


# ---------------------------------------------------------------------------
# DB-backed counting + password-spray escalation
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock


class _LogRow:
    def __init__(self, message):
        self.message = message


def _db_returning(messages):
    """Mock DB whose Log query returns rows with the given messages."""
    db = MagicMock()
    rows = [_LogRow(m) for m in messages]
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = rows
    return db


def test_db_count_crosses_threshold_with_empty_buffer():
    # Simulates a restart: the in-memory buffer is empty, but the DB already
    # holds prior failures, so the current failure crosses the threshold.
    db = _db_returning([f"Failed password for root from 10.9.9.9 port 22 ssh2"] * 5)
    bf = SSHBruteForceEngine(
        buffer=SSHFailureBuffer(), dedup=SSHBFDedupCache(), threshold=5, db=db
    )
    match = bf.evaluate(_failed_ssh_event(source_ip="10.9.9.9", agent_id="agent-db"))
    assert match is not None
    assert match.failure_count == 5


def test_db_error_falls_back_to_buffer():
    db = MagicMock()
    db.query.side_effect = RuntimeError("db down")
    bf = SSHBruteForceEngine(
        buffer=SSHFailureBuffer(), dedup=SSHBFDedupCache(), threshold=3, db=db
    )
    event = _failed_ssh_event(source_ip="10.8.8.8", agent_id="agent-fb")
    # Buffer path: needs 3 failures to trigger.
    assert bf.evaluate(event) is None
    assert bf.evaluate(event) is None
    assert bf.evaluate(event) is not None


def test_password_spray_escalates_risk():
    messages = [
        f"Failed password for {u} from 10.7.7.7 port 22 ssh2"
        for u in ["root", "admin", "oracle", "postgres", "deploy"]
    ]
    db = _db_returning(messages)
    bf = SSHBruteForceEngine(
        buffer=SSHFailureBuffer(), dedup=SSHBFDedupCache(), threshold=5, db=db
    )
    match = bf.evaluate(_failed_ssh_event(source_ip="10.7.7.7", agent_id="agent-spray"))
    assert match is not None
    assert match.risk_score == 55  # base 45 + spray bonus 10
    assert any("spraying" in r.lower() for r in match.match_reasons)


def test_single_username_no_spray_bonus():
    messages = [f"Failed password for root from 10.6.6.6 port 22 ssh2"] * 5
    db = _db_returning(messages)
    bf = SSHBruteForceEngine(
        buffer=SSHFailureBuffer(), dedup=SSHBFDedupCache(), threshold=5, db=db
    )
    match = bf.evaluate(_failed_ssh_event(source_ip="10.6.6.6", agent_id="agent-single"))
    assert match is not None
    assert match.risk_score == 45  # no spray bonus
    assert match.user_name == "root"
