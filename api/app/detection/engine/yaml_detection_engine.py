"""
Standalone YAML Detection Engine orchestrator for testing and advanced rule evaluation.
"""
from typing import List, Dict, Any, Optional
from pathlib import Path
from pydantic import BaseModel, Field
from .rule_loader import RuleLoader
from .rule_evaluator import RuleEvaluator, RuleMatchResult
from .risk_scoring import RiskScorer, RiskScoreResult
from .suppressions import SuppressionEngine, SuppressionResult
from ..schemas.rule_schema import DetectionRule

class DetectionCandidate(BaseModel):
    rule_id: str
    rule_name: str
    matched: bool
    suppressed: bool
    severity: str
    risk_score: int
    base_risk_score: int
    match_reasons: List[str] = Field(default_factory=list)
    adjustment_reasons: List[str] = Field(default_factory=list)
    suppression_id: Optional[str] = None
    suppression_reason: Optional[str] = None
    missing_fields: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    mitre: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

class YAMLDetectionEngine:
    def __init__(self, rules_path: Optional[Path] = None):
        self.loader = RuleLoader(rules_path)
        self.evaluator = RuleEvaluator()
        self.scorer = RiskScorer(self.evaluator)
        self.suppressor = SuppressionEngine(evaluator=self.evaluator)

    def evaluate_event(
        self, 
        event: Dict[str, Any], 
        include_disabled: bool = False, 
        return_unmatched: bool = False, 
        include_suppressed: bool = True
    ) -> List[DetectionCandidate]:
        """
        Evaluate a normalized event against all loaded YAML rules.
        """
        candidates = []
        
        # 1. Load rules
        rules = self.loader.load_rules_from_directory(self.loader.rules_path, include_disabled=include_disabled)
        
        # Add any loader errors to the first candidate or a dummy one? 
        # Requirement says: "does not crash if one rule is invalid and records/propagates loader error if possible"
        # I'll check self.loader.errors
        loader_errors = self.loader.errors.copy()
        
        for rule in rules:
            try:
                # Gate: skip rule if any required field is absent
                missing = [
                    f for f in rule.required_fields
                    if self.evaluator.get_field_value(event, f) is None
                ]
                if missing:
                    if return_unmatched:
                        candidates.append(DetectionCandidate(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            matched=False,
                            suppressed=False,
                            severity="informational",
                            risk_score=0,
                            base_risk_score=rule.risk_score,
                            missing_fields=missing,
                            errors=[f"SkippedDueToMissingFields: {missing}"],
                            mitre=rule.mitre,
                            tags=rule.tags,
                        ))
                    continue

                # 2. Evaluate Rule Match
                match_result = self.evaluator.evaluate(event, rule)
                
                if not match_result.matched and not return_unmatched:
                    continue
                
                # 3. Calculate Risk Score
                risk_result = self.scorer.calculate(event, rule, match_result)
                
                # 4. Check for Suppressions
                suppression_result = self.suppressor.should_suppress(event, rule, match_result, risk_result)
                
                if suppression_result.suppressed and not include_suppressed:
                    continue

                # 5. Build Candidate
                candidate = DetectionCandidate(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    matched=match_result.matched,
                    suppressed=suppression_result.suppressed,
                    severity=risk_result.final_severity,
                    risk_score=risk_result.final_score,
                    base_risk_score=risk_result.base_score,
                    match_reasons=match_result.match_reasons,
                    adjustment_reasons=risk_result.adjustment_reasons,
                    suppression_id=suppression_result.suppression_id,
                    suppression_reason=suppression_result.suppression_reason,
                    missing_fields=match_result.missing_fields,
                    errors=match_result.errors + risk_result.errors + suppression_result.errors,
                    mitre=rule.mitre,
                    tags=rule.tags
                )
                
                # Attach loader errors to candidates if relevant or just once
                if loader_errors:
                    candidate.errors.extend([f"Loader error: {e}" for e in loader_errors])
                    loader_errors = [] # Only report once
                
                candidates.append(candidate)

            except Exception as e:
                # Fallback for unexpected failures per rule
                candidates.append(DetectionCandidate(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    matched=False,
                    suppressed=False,
                    severity="informational",
                    risk_score=0,
                    base_risk_score=rule.risk_score,
                    errors=[f"Engine error: {str(e)}"]
                ))

        return candidates
