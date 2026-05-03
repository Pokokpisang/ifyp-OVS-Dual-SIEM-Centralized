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
