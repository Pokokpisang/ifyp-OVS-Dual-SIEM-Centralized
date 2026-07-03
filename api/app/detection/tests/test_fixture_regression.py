"""
test_fixture_regression.py — end-to-end regression net.

Runs synthetic fixture events through the parser + YAML engine and pins the
expected (rule_id, matched, suppressed, score band) so future rule/tuning edits
that shift detection outcomes are caught. All fixtures are synthetic and
defensive-only.
"""
import pytest

from app.detection.engine.audit_parser import AuditdParser
from app.detection.tests.conftest import load_fixture

# (fixture, rule_id, expect_matched, expect_suppressed, min_score, max_score)
CASES = [
    ("t1059_curl_pipe_bash", "linux_t1059_shell_network_tool", True, False, 67, 100),
    ("t1059_base64_chmod", "linux_t1059_shell_network_tool", True, False, 90, 100),
    ("t1059_build_workflow_suppressed", "linux_t1059_shell_network_tool", None, None, None, None),
    ("t1543_attacker_service", "linux_t1543_002_systemd_service_persistence", True, False, 55, 100),
    ("t1543_dpkg_maintainer_suppressed", "linux_t1543_002_systemd_service_persistence", True, True, None, None),
    ("t1110_failed_auth", "linux_t1110_ssh_bruteforce", True, False, 40, 40),
    ("t1053_cron_attacker", "linux_t1053_003_cron_persistence", True, False, 55, 100),
    ("t1053_cron_dpkg_suppressed", "linux_t1053_003_cron_persistence", True, True, None, None),
    ("t1078_service_login_external", "linux_t1078_003_service_account_login", True, False, 80, 80),
    ("t1078_service_login_allowlisted", "linux_t1078_003_service_account_login", True, True, None, None),
    # Hyphenated service account through the raw-syslog parser path (regression for
    # the \w+ user-name truncation bug — www-data must not become "www").
    ("t1078_service_login_hyphenated", "linux_t1078_003_service_account_login", True, False, 80, 80),
]


@pytest.mark.parametrize("fixture,rule_id,matched,suppressed,min_s,max_s", CASES)
def test_fixture_detection_outcomes(yaml_engine, fixture, rule_id, matched, suppressed, min_s, max_s):
    event = AuditdParser.normalize_log(load_fixture(fixture))
    candidates = yaml_engine.evaluate_event(event, return_unmatched=True)
    cand = next((c for c in candidates if c.rule_id == rule_id), None)

    if matched is None:
        # Build-workflow: rule may not even match; if it does it must be suppressed.
        assert cand is None or (not cand.matched) or cand.suppressed
        return

    assert cand is not None, f"{fixture}: expected candidate for {rule_id}"
    assert cand.matched is matched
    assert cand.suppressed is suppressed
    if min_s is not None:
        assert min_s <= cand.risk_score <= max_s, (
            f"{fixture}: score {cand.risk_score} outside [{min_s},{max_s}]"
        )


def test_unmatched_benign_produces_no_alerts(yaml_engine):
    event = AuditdParser.normalize_log(load_fixture("unmatched_benign"))
    candidates = yaml_engine.evaluate_event(event)
    assert [c for c in candidates if c.matched] == []
