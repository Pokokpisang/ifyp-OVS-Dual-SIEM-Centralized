import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from ... import models
from .yaml_detection_engine import YAMLDetectionEngine, DetectionCandidate

logger = logging.getLogger("detection.active_runner")

class ActiveDetectionRunner:
    """
    Active runner for YAMLDetectionEngine.
    Evaluates events and creates REAL alerts in the database.
    """
    def __init__(self, db: Session):
        self.db = db
        self.engine = YAMLDetectionEngine()
        self.include_suppressed = os.getenv("YAML_DETECTION_INCLUDE_SUPPRESSED", "true").lower() == "true"
        self.return_unmatched = os.getenv("YAML_DETECTION_RETURN_UNMATCHED", "false").lower() == "true"

    def run(self, normalized_event: Dict[str, Any]):
        """
        Evaluate event and trigger alert creation for matches.
        """
        try:
            candidates = self.engine.evaluate_event(
                normalized_event,
                include_suppressed=self.include_suppressed,
                return_unmatched=self.return_unmatched
            )

            for candidate in candidates:
                if candidate.matched and not candidate.suppressed:
                    self._create_alert(normalized_event, candidate)
                elif candidate.matched and candidate.suppressed:
                    logger.info(f"[ACTIVE_RUNNER] SUPPRESSED match: {candidate.rule_id}")
                
        except Exception as e:
            logger.error(f"[ACTIVE_RUNNER] Error during YAML evaluation: {e}", exc_info=True)

    def _create_alert(self, event: Dict[str, Any], candidate: DetectionCandidate):
        """
        Convert a DetectionCandidate into a persistent models.Alert.
        """
        host = event.get("hostname", event.get("host", "unknown"))
        mitre_info = candidate.mitre or {}
        
        # Build description
        description = f"{candidate.rule_name}. Reasons: {', '.join(candidate.match_reasons)}"
        if candidate.adjustment_reasons:
            description += f" | Risk Adjustments: {', '.join(candidate.adjustment_reasons)}"
        
        raw_log = event.get("message", "No raw message available")
        description += f"\n\nRAW_LOG: {raw_log}"

        # Metadata for UI
        metadata = {
            "match_reasons": candidate.match_reasons,
            "adjustment_reasons": candidate.adjustment_reasons,
            "base_risk_score": candidate.base_risk_score,
            "tags": candidate.tags,
            "errors": candidate.errors
        }

        # Extract IDs from MITRE dictionaries if they are dicts
        tactic = mitre_info.get("tactic", "Unknown")
        if isinstance(tactic, dict):
            tactic = tactic.get("id", tactic.get("name", "Unknown"))
            
        technique = mitre_info.get("technique", "Unknown")
        if isinstance(technique, dict):
            technique = technique.get("id", technique.get("name", "Unknown"))

        alert = models.Alert(
            timestamp=datetime.utcnow(),
            host=host,
            severity=candidate.severity.upper(),
            title=f"[{candidate.rule_id}] {candidate.rule_name}",
            description=description,
            source=str(technique),
            
            # v2.0.0 Fields
            rule_id=candidate.rule_id,
            rule_name=candidate.rule_name,
            risk_score=candidate.risk_score,
            mitre_tactic=str(tactic),
            mitre_technique=str(technique),
            detection_engine="YAML",
            detection_metadata=json.dumps(metadata)
        )

        self.db.add(alert)
        self.db.commit()
        logger.info(f"[ACTIVE_RUNNER] ALERT CREATED: {candidate.rule_id} on {host} (Risk: {candidate.risk_score})")
        print(f"[*] YAML ALERT CREATED: {candidate.rule_id} on {host} (Risk: {candidate.risk_score})")
