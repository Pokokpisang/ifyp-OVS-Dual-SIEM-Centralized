"""
Detection suppressions module.
"""
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from ..schemas.rule_schema import DetectionRule
from .rule_evaluator import RuleEvaluator, RuleMatchResult
from .risk_scoring import RiskScoreResult

class SuppressionResult(BaseModel):
    suppressed: bool = False
    suppression_id: Optional[str] = None
    suppression_reason: Optional[str] = None
    matched_suppressions: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

class SuppressionEngine:
    def __init__(self, tuning_path: Optional[Path] = None, evaluator: Optional[RuleEvaluator] = None):
        self.tuning_path = tuning_path or Path(__file__).parent.parent / "tuning"
        self.evaluator = evaluator or RuleEvaluator()
        self.global_suppressions: List[Dict[str, Any]] = []
        self.linux_suppressions: List[Dict[str, Any]] = []
        self.rule_exceptions: List[Dict[str, Any]] = []
        self.load_tuning_files()

    def load_tuning_files(self) -> None:
        """
        Load suppression rules from YAML files.
        """
        files = {
            "global_suppressions.yaml": "global_suppressions",
            "linux_suppressions.yaml": "linux_suppressions",
            "rule_exceptions.yaml": "rule_exceptions"
        }

        for filename, key in files.items():
            path = self.tuning_path / filename
            if not path.exists():
                # Silently skip missing files as per requirements, maybe log internally
                continue
            
            try:
                with open(path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and key in data:
                        setattr(self, key, data[key])
            except Exception as e:
                # Should probably have a way to report this, but for now we follow 'do not crash'
                pass

    def should_suppress(self, event: Dict[str, Any], rule: DetectionRule, match_result: RuleMatchResult, risk_result: RiskScoreResult) -> SuppressionResult:
        result = SuppressionResult()

        if not match_result.matched:
            return result

        # Check all categories of suppressions
        all_suppressions = [
            ("rule_exception", self.rule_exceptions),
            ("linux_suppression", self.linux_suppressions),
            ("global_suppression", self.global_suppressions)
        ]

        for category, suppressions in all_suppressions:
            for supp in suppressions:
                try:
                    if not supp.get("enabled", True):
                        continue

                    # 1. Rule Exception specific check
                    if category == "rule_exception":
                        if supp.get("rule_id") != rule.id:
                            continue

                    # 2. Platform/Scope check
                    scope = supp.get("scope", {})
                    if "platform" in scope:
                        platforms = scope["platform"]
                        # Check if rule platform overlaps or event platform (if event has one)
                        # For now, we assume if rule is linux and suppression is linux, it applies
                        rule_platforms = rule.platform
                        if not any(p in platforms for p in rule_platforms):
                            continue

                    # 3. High Risk Safety Check
                    is_high_risk = risk_result.final_severity in ["high", "critical"]
                    if is_high_risk and not supp.get("allow_high_risk", False):
                        continue

                    # 4. Condition Match
                    conditions = supp.get("conditions")
                    if conditions:
                        matched, _ = self.evaluator.evaluate_condition(event, conditions)
                        if matched:
                            result.suppressed = True
                            result.suppression_id = supp.get("id")
                            result.suppression_reason = supp.get("reason")
                            result.matched_suppressions.append(supp.get("id"))
                            return result # First match wins for suppression

                except Exception as e:
                    result.errors.append(f"Error in {category} '{supp.get('id', 'unknown')}': {str(e)}")

        return result

# Legacy/Global list for backward compatibility with existing non-YAML engine
GLOBAL_EXCLUSIONS = [
    "pg_isready",
    "/_cluster/health",
    "api/agent/rules",
    "docker-gen",
    "container_health_check"
]
