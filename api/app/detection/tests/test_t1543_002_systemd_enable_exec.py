import pytest
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

RULE_ID = "linux_t1543_002_systemd_enable_exec"


@pytest.fixture
def engine():
    return YAMLDetectionEngine()


def _attacker_enable_event():
    """Real telemetry pattern observed on a live host: `systemctl enable --now
    <suspicious-unit>` run interactively via sudo, with no corresponding
    auditd file-write event ever captured for the .service file (the sibling
    file-write rule stayed silent for this exact activity across two weeks)."""
    return {
        "process": {
            "name": "systemctl",
            "command_line": "systemctl enable --now threatactor-backdoor",
            "executable": "/usr/bin/systemctl",
            "parent": {"name": "bash"},
        },
        "user": {"name": "ahmad"},
        "host": {"name": "prod2"},
    }


def _package_manager_enable_event():
    """Legitimate provisioning: apt's maintainer script enabling a freshly
    installed service, no --now, no interactive shell."""
    return {
        "process": {
            "name": "systemctl",
            "command_line": "systemctl enable nginx.service",
            "executable": "/usr/bin/systemctl",
            "parent": {"name": "apt"},
        },
        "user": {"name": "root"},
        "host": {"name": "prod2"},
    }


def _systemctl_status_event():
    return {
        "process": {
            "name": "systemctl",
            "command_line": "systemctl status nginx",
            "executable": "/usr/bin/systemctl",
        },
        "user": {"name": "admin"},
        "host": {"name": "prod2"},
    }


def _systemctl_disable_event():
    """`disable` contains the substring 'enable' — regression guard against
    a naive substring match that would misfire on the opposite action."""
    return {
        "process": {
            "name": "systemctl",
            "command_line": "systemctl disable threatactor-backdoor",
            "executable": "/usr/bin/systemctl",
        },
        "user": {"name": "admin"},
        "host": {"name": "prod2"},
    }


# ---------------------------------------------------------------------------
# Positive detection tests
# ---------------------------------------------------------------------------


def test_matches_attacker_systemctl_enable(engine):
    candidates = engine.evaluate_event(_attacker_enable_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None, f"Expected {RULE_ID} candidate"
    assert t1543.matched is True
    assert t1543.suppressed is False


def test_risk_score_increases_for_shell_parent_now_flag_and_keyword(engine):
    """The real attack event hits all three increase_if adjustments:
    --now, bash parent, and the 'backdoor' keyword — score should climb
    well above the 50 base."""
    candidates = engine.evaluate_event(_attacker_enable_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.risk_score >= 50 + 10 + 15 + 20 - 1  # allow for scoring rounding, still well above base


# ---------------------------------------------------------------------------
# Negative / suppression tests
# ---------------------------------------------------------------------------


def test_package_manager_enable_is_suppressed(engine):
    """Reuses the existing global 'benign_package_manager_service_write'
    suppression — no new suppression file needed since it keys on
    process.parent.name, not rule_id."""
    candidates = engine.evaluate_event(_package_manager_enable_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.matched is True
    assert t1543.suppressed is True
    assert t1543.suppression_id == "benign_package_manager_service_write"


def test_no_match_systemctl_status(engine):
    candidates = engine.evaluate_event(_systemctl_status_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is None or t1543.matched is False


def test_no_match_systemctl_disable(engine):
    """'disable' contains 'enable' as a substring — must not false-positive."""
    candidates = engine.evaluate_event(_systemctl_disable_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is None or t1543.matched is False


def test_no_match_non_systemctl_process(engine):
    event = _attacker_enable_event()
    event["process"]["name"] = "bash"
    candidates = engine.evaluate_event(event, return_unmatched=True)
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.matched is False


# ---------------------------------------------------------------------------
# Metadata / evidence tests
# ---------------------------------------------------------------------------


def test_rule_has_correct_mitre_metadata(engine):
    candidates = engine.evaluate_event(_attacker_enable_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.mitre.get("technique", {}).get("id") == "T1543"
    assert t1543.mitre.get("subtechnique", {}).get("id") == "T1543.002"
    assert t1543.mitre.get("tactic", {}).get("id") == "TA0003"


def test_match_reasons_present(engine):
    candidates = engine.evaluate_event(_attacker_enable_event())
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert len(t1543.match_reasons) >= 1, "Evidence summary requires at least one match_reason"


def test_skips_missing_process_name(engine):
    event = _attacker_enable_event()
    del event["process"]["name"]
    candidates = engine.evaluate_event(event, return_unmatched=True)
    t1543 = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert t1543 is not None
    assert t1543.matched is False
    assert "process.name" in t1543.missing_fields
