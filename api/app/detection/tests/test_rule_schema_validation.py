"""
test_rule_schema_validation.py — condition & risk_adjustment structural
validation, plus a lint test over the real rules/ and tuning/ directories.
"""
import pytest
import yaml

from app.detection.engine.rule_loader import RuleLoader
from app.detection.engine.suppressions import SuppressionEngine
from app.detection.engine.rule_evaluator import RuleEvaluator
from app.detection.schemas.rule_schema import (
    DetectionRule,
    _validate_condition_node,
    _validate_risk_adjustment,
)


def _base_rule(**overrides):
    data = {
        "id": "r",
        "name": "R",
        "description": "d",
        "severity": "medium",
        "risk_score": 50,
        "mitre": {"tactic": {"id": "TA0002"}},
        "log_source": {"product": "linux"},
        "required_fields": ["process.name"],
        "condition": {"field": "process.name", "operator": "equals", "value": "bash"},
        "investigation_guide": "g",
    }
    data.update(overrides)
    return data


# --- condition tree --------------------------------------------------------

def test_valid_nested_condition_passes():
    cond = {
        "all": [
            {"field": "process.name", "operator": "in", "value": ["bash", "sh"]},
            {"any": [
                {"field": "cmd", "operator": "contains_any", "value": ["curl"]},
                {"field": "process.parent.name", "operator": "not_exists"},
            ]},
        ]
    }
    DetectionRule(**_base_rule(condition=cond))  # must not raise


def test_unknown_operator_rejected():
    with pytest.raises(Exception) as exc:
        DetectionRule(**_base_rule(condition={"field": "x", "operator": "startswith", "value": "y"}))
    assert "unknown operator" in str(exc.value)


def test_leaf_missing_value_rejected():
    with pytest.raises(Exception) as exc:
        DetectionRule(**_base_rule(condition={"field": "x", "operator": "equals"}))
    assert "requires a 'value'" in str(exc.value)


def test_exists_without_value_allowed():
    DetectionRule(**_base_rule(condition={"field": "x", "operator": "exists"}))


def test_unexpected_leaf_key_rejected():
    with pytest.raises(Exception) as exc:
        DetectionRule(**_base_rule(
            condition={"field": "x", "operator": "equals", "value": "y", "typo": 1}
        ))
    assert "unexpected keys" in str(exc.value)


def test_empty_all_list_rejected():
    with pytest.raises(Exception):
        DetectionRule(**_base_rule(condition={"all": []}))


# --- risk_adjustment -------------------------------------------------------

def test_legacy_conditions_increase_by_rejected():
    adj = {"increase_if": [{"conditions": {"all": []}, "increase_by": 5, "reason": "x"}]}
    with pytest.raises(Exception):
        DetectionRule(**_base_rule(risk_adjustment=adj))


def test_valid_adjustment_passes():
    adj = {"increase_if": [
        {"field": "cmd", "operator": "contains_any", "value": ["base64"], "add_score": 10, "reason": "r"}
    ]}
    DetectionRule(**_base_rule(risk_adjustment=adj))


def test_adjustment_missing_score_rejected():
    adj = {"increase_if": [{"field": "cmd", "operator": "exists", "reason": "r"}]}
    with pytest.raises(Exception) as exc:
        DetectionRule(**_base_rule(risk_adjustment=adj))
    assert "missing 'add_score'" in str(exc.value)


def test_adjustment_non_int_score_rejected():
    adj = {"increase_if": [{"field": "cmd", "operator": "exists", "add_score": "ten"}]}
    with pytest.raises(Exception):
        DetectionRule(**_base_rule(risk_adjustment=adj))


# --- lint the shipped rules + tuning --------------------------------------

def test_all_shipped_rules_load_without_errors():
    loader = RuleLoader()
    loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    assert loader.errors == [], f"Shipped rules failed schema validation: {loader.errors}"


def test_all_tuning_suppressions_have_valid_conditions():
    """Suppression/exception condition blocks must use the same operator grammar."""
    engine = SuppressionEngine(evaluator=RuleEvaluator())
    groups = {
        "global_suppressions": engine.global_suppressions,
        "linux_suppressions": engine.linux_suppressions,
        "rule_exceptions": engine.rule_exceptions,
    }
    for group_name, entries in groups.items():
        for entry in entries:
            conditions = entry.get("conditions")
            if conditions is None:
                continue
            _validate_condition_node(
                conditions, f"{group_name}:{entry.get('id', '?')}"
            )
