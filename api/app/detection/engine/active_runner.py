import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from ... import models
from .yaml_detection_engine import YAMLDetectionEngine, DetectionCandidate
from .correlation_engine import (
    ENABLE_CORRELATION_ENGINE,
    CorrelationEngine,
    CorrelationMatch,
    get_process_event_buffer,
    get_dedup_cache,
)

logger = logging.getLogger("detection.active_runner")

# Log types that carry no process-level events — skip correlation for these
_NON_PROCESS_LOG_TYPES = frozenset({
    "metric",
    "metrics",
    "heartbeat",
    "system_health",
    "health_check",
})


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

            yaml_fired_t1059 = False

            for candidate in candidates:
                if candidate.matched and not candidate.suppressed:
                    self._create_alert(normalized_event, candidate)
                    if candidate.mitre.get("technique", {}) in ("T1059.004", "T1059"):
                        yaml_fired_t1059 = True
                    # Check by dict id too
                    tech = candidate.mitre.get("technique", {})
                    if isinstance(tech, dict) and tech.get("id", "") in ("T1059.004", "T1059"):
                        yaml_fired_t1059 = True
                elif candidate.matched and candidate.suppressed:
                    logger.info(f"[ACTIVE_RUNNER] SUPPRESSED match: {candidate.rule_id}")

        except Exception as e:
            logger.error(f"[ACTIVE_RUNNER] Error during YAML evaluation: {e}", exc_info=True)
            yaml_fired_t1059 = False

        # --- Correlation Engine ---
        if ENABLE_CORRELATION_ENGINE:
            self._run_correlation(normalized_event, yaml_fired_t1059)

    # -----------------------------------------------------------------------
    # Correlation pass
    # -----------------------------------------------------------------------

    def _run_correlation(self, event: Dict[str, Any], yaml_already_fired: bool) -> None:
        """Run lightweight correlation engine for multi-event attack patterns."""
        # Only run for process/audit events — skip metrics, heartbeat, etc.
        log_type = str(event.get("log_type", "")).lower()
        if log_type in _NON_PROCESS_LOG_TYPES:
            return

        # Must have a process.name field to be relevant
        process_name = ""
        if isinstance(event.get("process"), dict):
            process_name = event["process"].get("name", "")
        if not process_name:
            return

        try:
            corr_engine = CorrelationEngine(
                buffer=get_process_event_buffer(),
                dedup=get_dedup_cache(),
            )
            match = corr_engine.evaluate(event)
        except Exception as e:
            logger.error(f"[CORR] Correlation engine error: {e}", exc_info=True)
            return

        if not match:
            return

        # DB-level dedup: if the strict YAML T1059 rule already created an alert
        # for the same agent + T1059.004 + containing the same URL in the last
        # CORRELATION_DEDUP_SECONDS, skip the correlation alert.
        if yaml_already_fired or self._yaml_alert_exists_recently(match):
            logger.info(
                f"[CORR] Skipping correlation alert — strict YAML rule already "
                f"fired for agent={match.agent_id}"
            )
            return

        self._create_correlation_alert(event, match)

    def _yaml_alert_exists_recently(self, match: CorrelationMatch) -> bool:
        """
        Check the DB for a recent strict YAML T1059 alert on the same agent
        with the same MITRE technique and (optionally) the same URL.
        """
        from .correlation_engine import CORRELATION_DEDUP_SECONDS
        cutoff = datetime.utcnow() - timedelta(seconds=CORRELATION_DEDUP_SECONDS)
        query = self.db.query(models.Alert).filter(
            models.Alert.agent_id == match.agent_id,
            models.Alert.mitre_technique == match.mitre_technique,
            models.Alert.timestamp >= cutoff,
        )
        if match.source_url:
            query = query.filter(
                models.Alert.description.contains(match.source_url)
            )
        return query.first() is not None

    def _create_correlation_alert(
        self, event: Dict[str, Any], match: CorrelationMatch
    ) -> None:
        """Create a standard Alert record for a correlation hit."""
        host = event.get("hostname", event.get("host", "unknown"))
        if isinstance(host, dict):
            host = host.get("name", "unknown")

        detection_metadata = {
            "first_event_process": match.first_event_process,
            "first_event_command": match.first_event_command,
            "second_event_process": match.second_event_process,
            "second_event_command": match.second_event_command,
            "time_delta_seconds": match.time_delta_seconds,
            "correlation_window_seconds": match.correlation_window_seconds,
            "reason": match.reason,
            "source_url": match.source_url,
            "optional_keys": match.optional_keys,
        }

        description = (
            f"{match.rule_name}. {match.reason}"
            f"\n\nFirst Event: [{match.first_event_process}] {match.first_event_command}"
            f"\nSecond Event: [{match.second_event_process}] {match.second_event_command}"
            f"\nTime Delta: {match.time_delta_seconds}s"
        )

        alert = models.Alert(
            timestamp=datetime.utcnow(),
            host=str(host),
            severity=match.severity.upper(),
            title=f"[{match.rule_id}] {match.rule_name}",
            description=description,
            source=match.mitre_technique,

            # v2.0.0 Fields
            agent_id=match.agent_id,
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            risk_score=match.risk_score,
            mitre_tactic=match.mitre_tactic,
            mitre_technique=match.mitre_technique,
            detection_engine="CorrelationEngine",
            detection_metadata=json.dumps(detection_metadata),
        )

        self.db.add(alert)
        self.db.commit()
        logger.info(
            f"[CORR] ALERT CREATED: {match.rule_id} on {host} "
            f"(Risk: {match.risk_score}, delta={match.time_delta_seconds}s)"
        )

    # -----------------------------------------------------------------------
    # Standard YAML alert creator (unchanged)
    # -----------------------------------------------------------------------

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
            agent_id=event.get("agent_id"),
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
