import pytest
from pathlib import Path
import yaml
from app.detection.engine.rule_loader import RuleLoader
from app.detection.schemas.rule_schema import DetectionRule

def test_rule_loader_loads_sample_disabled_rule():
    loader = RuleLoader()
    # The sample rule is at app/detection/rules/linux/execution/t1059/sample_t1059_shell_network_tool.yaml
    # RuleLoader by default looks in app/detection/rules
    rules = loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    
    assert len(rules) >= 1
    sample_rule = next((r for r in rules if r.id == "linux_t1059_shell_network_tool_sample"), None)
    assert sample_rule is not None
    assert sample_rule.enabled is False
    assert sample_rule.severity == "medium"

def test_rule_loader_skips_disabled_rules_by_default():
    loader = RuleLoader()
    rules = loader.load_all_rules()
    
    # If the only rule is the sample one which is disabled, this should be empty
    # unless other rules exist.
    sample_rule = next((r for r in rules if r.id == "linux_t1059_shell_network_tool_sample"), None)
    assert sample_rule is None

def test_rule_loader_handles_invalid_yaml(tmp_path):
    # Create a bad YAML file
    bad_file = tmp_path / "bad_rule.yaml"
    bad_file.write_text("invalid: yaml: :")
    
    loader = RuleLoader()
    rule = loader.load_rule_file(bad_file)
    
    assert rule is None
    assert len(loader.errors) > 0
    assert "bad_rule.yaml" in loader.errors[0]["file"]

def test_rule_loader_handles_schema_validation_error(tmp_path):
    # Create a rule with invalid severity
    bad_rule = {
        "id": "invalid_severity",
        "name": "Invalid Severity Rule",
        "description": "Rule with bad severity",
        "severity": "super_high", # Invalid
        "risk_score": 50,
        "mitre": {"tactic": "execution"},
        "condition": {"field": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["test"],
        "investigation_guide": "test"
    }
    rule_file = tmp_path / "invalid_rule.yaml"
    with open(rule_file, "w") as f:
        yaml.dump(bad_rule, f)
        
    loader = RuleLoader()
    rule = loader.load_rule_file(rule_file)
    
    assert rule is None
    assert len(loader.errors) > 0
    assert "severity" in loader.errors[0]["error"]

def test_detection_rule_rejects_high_risk_score():
    bad_data = {
        "id": "high_risk",
        "name": "High Risk Rule",
        "description": "Rule with risk score > 100",
        "severity": "medium",
        "risk_score": 150, # Invalid
        "mitre": {"tactic": "execution"},
        "condition": {"field": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["test"],
        "investigation_guide": "test"
    }
    with pytest.raises(Exception):
        DetectionRule(**bad_data)

if __name__ == "__main__":
    # Simple manual test if pytest is not available
    loader = RuleLoader()
    rules = loader.load_all_rules()
    print(f"Loaded {len(rules)} enabled rules")
    
    all_rules = loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    print(f"Loaded {len(all_rules)} total rules (including disabled)")
    
    for error in loader.errors:
        print(f"Error in {error['file']}: {error['error']}")
