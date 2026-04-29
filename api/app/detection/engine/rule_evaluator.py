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
            
            # Special case for 'exists' operator which doesn't need a value comparison in the same way
            if operator == "exists":
                if actual_value is not None:
                    return True, [f"Field '{field}' exists"]
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

        return False, ""


# ---------------------------------------------------------------------------
# Legacy module-level functions — kept for backward compatibility with
# detection_engine.py (legacy RuleEngine). Do NOT remove until the full
# migration to YAMLDetectionEngine is complete.
# ---------------------------------------------------------------------------

def normalize_logic(logic: dict) -> dict:
    """Normalize legacy rule logic JSON to a consistent structure."""
    if "match" not in logic:
        match_block = {}
        if "keywords" in logic:
            match_block["keywords_any"] = logic["keywords"]
        if "patterns" in logic:
            match_block["patterns_any"] = logic["patterns"]
        logic["match"] = match_block
    if "exclude" not in logic:
        logic["exclude"] = {}
    if "alert" not in logic:
        logic["alert"] = {}
    return logic


def match_conditions(content: str, match_logic: dict):
    """
    Legacy match function for DB-based rule evaluation.
    Returns (matched, reason, tokens, severity).
    """
    matched = False
    reason = ""
    tokens = []
    severity = None

    if "patterns_any" in match_logic:
        for pattern in match_logic["patterns_any"]:
            all_found = True
            temp_tokens = []
            for part in pattern.get("all_of", []):
                if "|" in part:
                    options = part.split("|")
                    found_opt = False
                    for opt in options:
                        opt_text = opt.strip()
                        if not opt_text:
                            continue
                        regex_parts = []
                        if opt_text[0].isalnum():
                            regex_parts.append(r'(?<!\w)')
                        regex_parts.append(re.escape(opt_text))
                        if opt_text[-1].isalnum():
                            regex_parts.append(r'(?!\w)')
                        if re.search("".join(regex_parts), content, re.IGNORECASE):
                            found_opt = True
                            temp_tokens.append(opt_text)
                            break
                    if not found_opt:
                        all_found = False
                        break
                else:
                    regex_parts = []
                    if part[0].isalnum():
                        regex_parts.append(r'(?<!\w)')
                    regex_parts.append(re.escape(part))
                    if part[-1].isalnum():
                        regex_parts.append(r'(?!\w)')
                    if not re.search("".join(regex_parts), content, re.IGNORECASE):
                        all_found = False
                        break
                    else:
                        temp_tokens.append(part)

            if all_found and len(pattern.get("all_of", [])) > 0:
                matched = True
                reason = f"Pattern match: {pattern.get('name', 'unnamed')}"
                tokens = temp_tokens
                severity = pattern.get("severity")
                break

    if not matched and "keywords_all" in match_logic:
        kws = match_logic["keywords_all"]
        if kws:
            all_found = True
            temp_tokens = []
            for kw in kws:
                regex_parts = []
                if kw[0].isalnum():
                    regex_parts.append(r'(?<!\w)')
                regex_parts.append(re.escape(kw))
                if kw[-1].isalnum():
                    regex_parts.append(r'(?!\w)')
                if re.search("".join(regex_parts), content, re.IGNORECASE):
                    temp_tokens.append(kw)
                else:
                    all_found = False
                    break
            if all_found:
                matched = True
                reason = "Keywords ALL match"
                tokens = temp_tokens

    if not matched and "keywords_any" in match_logic:
        for kw in match_logic["keywords_any"]:
            regex_parts = []
            if kw[0].isalnum():
                regex_parts.append(r'(?<!\w)')
            regex_parts.append(re.escape(kw))
            if kw[-1].isalnum():
                regex_parts.append(r'(?!\w)')
            if re.search("".join(regex_parts), content, re.IGNORECASE):
                matched = True
                reason = f"Keyword ANY match: {kw}"
                tokens.append(kw)
                break

    return matched, reason, tokens, severity


import ipaddress

def exclude_conditions(content: str, raw_log: dict, exclude_logic: dict):
    """Legacy exclude function for DB-based rule evaluation."""
    if not exclude_logic:
        return False, ""

    if "keywords_any" in exclude_logic:
        for kw in exclude_logic["keywords_any"]:
            if kw.lower() in content.lower():
                return True, f"Exclude Keyword ANY: {kw}"

    if "keywords_all" in exclude_logic:
        kws = exclude_logic["keywords_all"]
        if kws and all(kw.lower() in content.lower() for kw in kws):
            return True, "Exclude Keywords ALL match"

    proc_path = raw_log.get("process_path", raw_log.get("exe", ""))
    if "process_paths_any" in exclude_logic and proc_path:
        for p in exclude_logic["process_paths_any"]:
            if p in proc_path:
                return True, f"Exclude Process Path: {p}"

    user = raw_log.get("user", raw_log.get("username", ""))
    if "users_any" in exclude_logic and user:
        if user in exclude_logic["users_any"]:
            return True, f"Exclude User: {user}"

    src_ip = raw_log.get("src_ip", raw_log.get("source_ip", ""))
    if "source_ips_any" in exclude_logic and src_ip:
        if src_ip in exclude_logic["source_ips_any"]:
            return True, f"Exclude Source IP: {src_ip}"

    dst_ip = raw_log.get("dst_ip", raw_log.get("destination_ip", ""))
    if "destination_ips_any" in exclude_logic and dst_ip:
        if dst_ip in exclude_logic["destination_ips_any"]:
            return True, f"Exclude Dest IP: {dst_ip}"

    if exclude_logic.get("destination_ips_private") and dst_ip:
        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return True, "Exclude Dest IP: Private/Loopback"
        except ValueError:
            pass

    return False, ""
