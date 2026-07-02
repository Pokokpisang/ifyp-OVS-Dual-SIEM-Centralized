import pytest
from pathlib import Path
from unittest.mock import patch
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

def _valid_rule_dict(rule_id="cache_rule"):
    return {
        "id": rule_id,
        "name": "Cache Rule",
        "description": "d",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": {"id": "TA0002"}, "technique": {"id": "T1059"}},
        "condition": {"field": "process.name", "operator": "equals", "value": "bash"},
        "log_source": {"product": "linux"},
        "required_fields": ["process.name"],
        "investigation_guide": "g",
    }


def test_cache_avoids_reparsing_unchanged_files(tmp_path):
    (tmp_path / "r.yaml").write_text(yaml.dump(_valid_rule_dict()))
    loader = RuleLoader()

    loader.load_rules_from_directory(tmp_path, include_disabled=True)
    # Second call: unchanged mtime → yaml.safe_load must not be invoked again.
    with patch("app.detection.engine.rule_loader.yaml.safe_load") as mock_load:
        rules = loader.load_rules_from_directory(tmp_path, include_disabled=True)
    mock_load.assert_not_called()
    assert len(rules) == 1


def test_cache_reloads_when_file_changes(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text(yaml.dump(_valid_rule_dict(rule_id="v1")))
    loader = RuleLoader()
    r1 = loader.load_rules_from_directory(tmp_path, include_disabled=True)
    assert r1[0].id == "v1"

    # Rewrite with a newer mtime and different content.
    import os, time
    f.write_text(yaml.dump(_valid_rule_dict(rule_id="v2")))
    os.utime(f, (time.time() + 10, time.time() + 10))
    r2 = loader.load_rules_from_directory(tmp_path, include_disabled=True)
    assert r2[0].id == "v2"


def test_invalid_file_reported_every_call(tmp_path):
    (tmp_path / "bad.yaml").write_text("invalid: yaml: :")
    loader = RuleLoader()
    loader.load_rules_from_directory(tmp_path, include_disabled=True)
    assert any("bad.yaml" in e["file"] for e in loader.errors)
    # Errors are rebuilt (not accumulated) and the invalid file is re-reported.
    loader.load_rules_from_directory(tmp_path, include_disabled=True)
    assert len([e for e in loader.errors if "bad.yaml" in e["file"]]) == 1


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
