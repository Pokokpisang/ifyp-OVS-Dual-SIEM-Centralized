"""
Risk scoring module for YAML-based detection rules.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from ..schemas.rule_schema import DetectionRule
from .rule_evaluator import RuleEvaluator, RuleMatchResult

class RiskScoreResult(BaseModel):
    base_score: int
    final_score: int
    base_severity: str
    final_severity: str
    adjustment_reasons: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

class RiskScorer:
    def __init__(self, evaluator: Optional[RuleEvaluator] = None):
        self.evaluator = evaluator or RuleEvaluator()

    def _score_to_severity(self, score: int) -> str:
        """
        Maps a risk score to a severity level.
        0-20: informational
        21-40: low
        41-60: medium
        61-80: high
        81-100: critical
        """
        if score <= 20:
            return "informational"
        elif score <= 40:
            return "low"
        elif score <= 60:
            return "medium"
        elif score <= 80:
            return "high"
        else:
            return "critical"

    def calculate(self, event: Dict[str, Any], rule: DetectionRule, match_result: RuleMatchResult) -> RiskScoreResult:
        base_severity = rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity)
        
        if not match_result.matched:
            return RiskScoreResult(
                base_score=rule.risk_score,
                final_score=0,
                base_severity=base_severity,
                final_severity="informational",
                adjustment_reasons=["Rule did not match; risk scoring skipped"]
            )

        final_score = rule.risk_score
        adjustment_reasons = []
        errors = []

        if rule.risk_adjustment:
            # Apply increase_if
            increase_blocks = rule.risk_adjustment.get("increase_if", [])
            if not isinstance(increase_blocks, list):
                errors.append("risk_adjustment.increase_if must be a list")
            else:
                for block in increase_blocks:
                    try:
                        matched, _ = self.evaluator.evaluate_condition(event, block)
                        if matched:
                            add_score = block.get("add_score", 0)
                            final_score += add_score
                            reason = block.get("reason", "Risk increased due to matching condition")
                            adjustment_reasons.append(reason)
                    except Exception as e:
                        errors.append(f"Error in increase_if block: {str(e)}")

            # Apply decrease_if
            decrease_blocks = rule.risk_adjustment.get("decrease_if", [])
            if not isinstance(decrease_blocks, list):
                errors.append("risk_adjustment.decrease_if must be a list")
            else:
                for block in decrease_blocks:
                    try:
                        matched, _ = self.evaluator.evaluate_condition(event, block)
                        if matched:
                            sub_score = block.get("subtract_score", 0)
                            final_score -= sub_score
                            reason = block.get("reason", "Risk decreased due to matching condition")
                            adjustment_reasons.append(reason)
                    except Exception as e:
                        errors.append(f"Error in decrease_if block: {str(e)}")

        if not adjustment_reasons:
            adjustment_reasons.append("No risk adjustments applied")

        # Clamp final_score
        final_score = max(0, min(100, final_score))
        final_severity = self._score_to_severity(final_score)

        return RiskScoreResult(
            base_score=rule.risk_score,
            final_score=final_score,
            base_severity=base_severity,
            final_severity=final_severity,
            adjustment_reasons=adjustment_reasons,
            errors=errors
        )
