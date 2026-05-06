import pytest
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

RULE_ID = "linux_t1543_002_systemd_service_persistence"


@pytest.fixture
def engine():
    return YAMLDetectionEngine()


def _suspicious_service_creation_event():
    return {
        "event": {"category": "file", "type": "change", "action": "created"},
        "file": {
            "path": "/etc/systemd/system/backdoor.service",
            "name": "backdoor.service",
        },
        "process": {
            "name": "bash",
            "command_line": (
                "bash -c \"echo 'ExecStart=/tmp/payload.sh'"
                " > /etc/systemd/system/backdoor.service\""
            ),
            "executable": "/usr/bin/bash",
            "parent": {"name": "sshd"},
        },
        "user": {"name": "root"},
        "host": {"name": "dev-vps"},
    }


def _systemctl_status_event():
    return {
        "event": {"category": "process", "type": "start", "action": "execve"},
        "process": {
            "name": "systemctl",
            "command_line": "systemctl status nginx",
            "executable": "/usr/bin/systemctl",
        },
        "user": {"name": "admin"},
        "host": {"name": "dev-vps"},
    }


def _systemctl_restart_event():
    return {
        "event": {"category": "process", "type": "start", "action": "execve"},
        "process": {
            "name": "systemctl",
            "command_line": "systemctl restart nginx",
            "executable": "/usr/bin/systemctl",
        },
        "user": {"name": "admin"},
        "host": {"name": "dev-vps"},
    }


def _benign_service_file_write_event():
    """Package manager modifying a legitimate service file — no suspicious indicators."""
    return {
        "event": {"category": "file", "type": "change", "action": "modified"},
        "file": {
            "path": "/etc/systemd/system/nginx.service",
            "name": "nginx.service",
        },
        "process": {
            "name": "dpkg",
            "command_line": "dpkg --configure nginx",
            "executable": "/usr/bin/dpkg",
            "parent": {"name": "apt"},
        },
        "user": {"name": "root"},
        "host": {"name": "dev-vps"},
    }


# ---------------------------------------------------------------------------
# Positive detection tests
# ---------------------------------------------------------------------------


def test_t1543_matches_suspicious_service_creation(engine):
    candidates = engine.evaluate_event(_suspicious_service_creation_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None, f"Expected {RULE_ID} candidate"
    assert t1543.matched is True
    assert t1543.suppressed is False


# ---------------------------------------------------------------------------
# Negative detection tests
# ---------------------------------------------------------------------------


def test_t1543_no_match_systemctl_status(engine):
    candidates = engine.evaluate_event(_systemctl_status_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is None or t1543.matched is False


def test_t1543_no_match_systemctl_restart(engine):
    candidates = engine.evaluate_event(_systemctl_restart_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is None or t1543.matched is False


def test_t1543_no_match_benign_service_file_write(engine):
    """A legitimate .service file write with no suspicious payload indicators must not alert."""
    candidates = engine.evaluate_event(_benign_service_file_write_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is None or t1543.matched is False


# ---------------------------------------------------------------------------
# Metadata test
# ---------------------------------------------------------------------------


def test_t1543_rule_has_correct_mitre_metadata(engine):
    candidates = engine.evaluate_event(
        _suspicious_service_creation_event(), include_disabled=True
    )
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None, f"Expected {RULE_ID} candidate for metadata check"
    assert t1543.mitre.get("technique", {}).get("id") == "T1543"
    assert t1543.mitre.get("subtechnique", {}).get("id") == "T1543.002"
    assert t1543.mitre.get("tactic", {}).get("id") == "TA0003"


# ---------------------------------------------------------------------------
# Required-fields guard test
# ---------------------------------------------------------------------------


def test_t1543_skips_missing_file_path(engine):
    event = _suspicious_service_creation_event()
    del event["file"]

    candidates = engine.evaluate_event(event, return_unmatched=True)
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.matched is False
    assert "file.path" in t1543.missing_fields
