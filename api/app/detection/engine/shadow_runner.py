"""
Shadow mode runner for YAML-based detection engine.
Allows running the new detection engine alongside the legacy pipeline without affecting live alerts.
"""
import os
import logging
from typing import Dict, Any, List
from .yaml_detection_engine import YAMLDetectionEngine, DetectionCandidate

# Setup logging
logger = logging.getLogger("detection.shadow_mode")
logger.setLevel(logging.INFO)

class ShadowDetectionRunner:
    def __init__(self, engine: YAMLDetectionEngine = None):
        self.engine = engine or YAMLDetectionEngine()
        
        # Respect both the legacy flag and the new system mode
        mode = os.getenv("DETECTION_ENGINE_MODE", "YAML").upper()
        legacy_shadow = os.getenv("YAML_DETECTION_SHADOW_MODE", "false").lower() == "true"
        
        self.enabled = (mode == "SHADOW") or legacy_shadow
        self.include_suppressed = os.getenv("YAML_DETECTION_INCLUDE_SUPPRESSED", "true").lower() == "true"
        self.return_unmatched = os.getenv("YAML_DETECTION_RETURN_UNMATCHED", "false").lower() == "true"
        
        if self.enabled:
            print(f"[*] ShadowDetectionRunner initialized (ENABLED=true, mode={mode}, include_suppressed={self.include_suppressed})")
        else:
            # Add a one-time print if initialized but disabled to help debugging
            print(f"[!] ShadowDetectionRunner initialized (DISABLED, mode={mode})")

    def run(self, normalized_event: Dict[str, Any]):
        """
        Runs the YAML detection engine in shadow mode and logs the results.
        Never raises exceptions to the caller.
        """
        if not self.enabled:
            return

        try:
            candidates = self.engine.evaluate_event(
                normalized_event,
                include_disabled=False, # We only want to shadow real rules
                return_unmatched=self.return_unmatched,
                include_suppressed=self.include_suppressed
            )

            for candidate in candidates:
                self._log_candidate(candidate)

        except Exception as e:
            logger.error(f"Shadow mode engine error: {str(e)}", exc_info=True)

    def _log_candidate(self, c: DetectionCandidate):
        """
        Logs a detection candidate in a readable compact format.
        """
        status = "MATCHED" if c.matched else "NO_MATCH"
        if c.suppressed:
            status = "SUPPRESSED"
            
        log_msg = (
            f"[SHADOW_DETECTION] {status} | "
            f"rule_id: {c.rule_id} | "
            f"rule_name: {c.rule_name} | "
            f"severity: {c.severity} | "
            f"risk_score: {c.risk_score} (base: {c.base_risk_score}) | "
            f"reasons: {', '.join(c.match_reasons)} | "
            f"adjustments: {', '.join(c.adjustment_reasons)}"
        )
        
        if c.suppressed:
            log_msg += f" | suppression: {c.suppression_id} ({c.suppression_reason})"
            
        if c.errors:
            log_msg += f" | errors: {', '.join(c.errors)}"

        logger.info(log_msg)
        print(log_msg)

# Singleton instance for easy integration
_runner_instance = None

def get_shadow_runner() -> ShadowDetectionRunner:
    global _runner_instance
    if _runner_instance is None:
        _runner_instance = ShadowDetectionRunner()
    return _runner_instance
