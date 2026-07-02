"""
Rule evaluator module for executing YAML detection rules against security events.
"""
import re
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from ..schemas.rule_schema import DetectionRule

class RuleMatchResult(BaseModel):
    matched: bool = False
    rule_id: str
    rule_name: str
    base_risk_score: int
    severity: str
    match_reasons: List[str] = Field(default_factory=list)
    missing_fields: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

class RuleEvaluator:
    @staticmethod
    def get_field_value(event: Dict[str, Any], field_path: str) -> Any:
        """
        Extract a value from a nested dictionary using dot notation.
        Returns None if any part of the path is missing.
        """
        parts = field_path.split('.')
        current = event
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def evaluate(self, event: Dict[str, Any], rule: DetectionRule) -> RuleMatchResult:
        result = RuleMatchResult(
            rule_id=rule.id,
            rule_name=rule.name,
            base_risk_score=rule.risk_score,
            severity=rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity)
        )

        try:
            # Check for required fields first
            for field in rule.required_fields:
                if self.get_field_value(event, field) is None:
                    result.missing_fields.append(field)

            # Evaluate main condition
            matched, reasons = self._evaluate_condition_block(event, rule.condition, result)
            result.matched = matched
            result.match_reasons = reasons

        except Exception as e:
            result.errors.append(f"Evaluation error: {str(e)}")
            result.matched = False

        return result

    def evaluate_condition(self, event: Dict[str, Any], condition: Dict[str, Any]) -> (bool, List[str]):
        """
        Public helper to evaluate a condition block.
        """
        return self._evaluate_condition_block(event, condition, None)

    def _evaluate_condition_block(self, event: Dict[str, Any], condition: Dict[str, Any], result: Optional[RuleMatchResult]) -> (bool, List[str]):
        """
        Recursively evaluate a condition block (all, any, not, or a single condition).
        """
        reasons = []
        
        if "all" in condition:
            sub_results = []
            all_reasons = []
            for sub_cond in condition["all"]:
                res, res_reasons = self._evaluate_condition_block(event, sub_cond, result)
                sub_results.append(res)
                all_reasons.extend(res_reasons)
            if all(sub_results):
                return True, all_reasons
            return False, []

        if "any" in condition:
            for sub_cond in condition["any"]:
                res, res_reasons = self._evaluate_condition_block(event, sub_cond, result)
                if res:
                    return True, res_reasons
            return False, []

        if "not" in condition:
            res, res_reasons = self._evaluate_condition_block(event, condition["not"], result)
            if not res:
                return True, [f"NOT condition matched: {condition['not'].get('field', 'block')} did not match"]
            return False, []

        # Single condition
        if "field" in condition and "operator" in condition:
            field = condition["field"]
            operator = condition["operator"]
            expected_value = condition.get("value")
            
            actual_value = self.get_field_value(event, field)
            
            # Special cases for existence operators — these must be evaluable
            # even when the field is absent, so handle them before the
            # missing-field early-return below.
            if operator == "exists":
                if actual_value is not None:
                    return True, [f"Field '{field}' exists"]
                return False, []

            if operator == "not_exists":
                if actual_value is None:
                    return True, [f"Field '{field}' does not exist"]
                return False, []

            if actual_value is None:
                # If field is missing and it's not 'exists', it's a fail
                return False, []

            matched, reason = self._apply_operator(field, actual_value, operator, expected_value)
            if matched:
                return True, [reason]
            return False, []

        return False, []

    def _apply_operator(self, field: str, actual: Any, operator: str, expected: Any) -> (bool, str):
        """
        Apply the operator logic.
        """
        op = operator.lower()
        
        # Helper for case-insensitive string comparison
        def to_lower_str(v):
            if v is None: return ""
            return str(v).lower()

        actual_str = to_lower_str(actual)

        if op == "equals":
            if actual_str == to_lower_str(expected):
                return True, f"{field} equals '{expected}'"
        
        elif op == "not_equals":
            if actual_str != to_lower_str(expected):
                return True, f"{field} does not equal '{expected}'"

        elif op == "contains":
            if to_lower_str(expected) in actual_str:
                return True, f"{field} contains '{expected}'"

        elif op == "not_contains":
            if to_lower_str(expected) not in actual_str:
                return True, f"{field} does not contain '{expected}'"

        elif op == "contains_any":
            if isinstance(expected, list):
                for val in expected:
                    if to_lower_str(val) in actual_str:
                        return True, f"{field} contained one of {expected}"
            return False, ""

        elif op == "not_contains_any":
            if isinstance(expected, list):
                if not any(to_lower_str(val) in actual_str for val in expected):
                    return True, f"{field} does not contain any of {expected}"
            return False, ""

        elif op == "in":
            if isinstance(expected, list):
                if any(actual_str == to_lower_str(val) for val in expected):
                    return True, f"{field} matched in {expected}"
            return False, ""

        elif op == "not_in":
            if isinstance(expected, list):
                if not any(actual_str == to_lower_str(val) for val in expected):
                    return True, f"{field} not in {expected}"
            return False, ""

        elif op == "regex":
            try:
                if re.search(str(expected), str(actual), re.IGNORECASE):
                    return True, f"{field} matched regex '{expected}'"
            except re.error:
                pass
            return False, ""

        elif op == "contains_all":
            if isinstance(expected, list) and expected:
                if all(to_lower_str(val) in actual_str for val in expected):
                    return True, f"{field} contains all of {expected}"
            return False, ""

        elif op == "list_intersects":
            if isinstance(expected, list):
                actual_items = actual if isinstance(actual, list) else [actual]
                actual_lowers = {to_lower_str(a) for a in actual_items}
                if actual_lowers & {to_lower_str(v) for v in expected}:
                    return True, f"{field} intersects {expected}"
            return False, ""

        elif op in ("gte", "lte"):
            # Numeric comparison; fail closed (never raise) on non-numeric input.
            try:
                a_num = float(actual)
                e_num = float(expected)
            except (TypeError, ValueError):
                return False, ""
            if op == "gte" and a_num >= e_num:
                return True, f"{field} >= {expected}"
            if op == "lte" and a_num <= e_num:
                return True, f"{field} <= {expected}"
            return False, ""

        return False, ""
