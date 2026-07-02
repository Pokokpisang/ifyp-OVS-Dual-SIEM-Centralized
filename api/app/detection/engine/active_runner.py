import os
import hashlib
import logging
from datetime import datetime, timedelta, timezone
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
from .ssh_bruteforce_engine import (
    ENABLE_SSH_BRUTEFORCE_ENGINE,
    SSHBruteForceEngine,
    SSHBruteForceMatch,
    get_ssh_failure_buffer,
    get_ssh_bf_dedup,
)

from ...services.alert_service import AlertSpec, create_alert

logger = logging.getLogger("detection.active_runner")

YAML_DEDUP_WINDOW_SECONDS = 60
_GMT8 = timezone(timedelta(hours=8))


def _extract_event_epoch(event: dict) -> float:
    """Return a UTC epoch from the event, preferring embedded timestamps.

    Priority: @timestamp → timestamp → event.created → datetime.utcnow().
    Z suffix is normalised to +00:00 for Python 3.10 fromisoformat compatibility.
    Naive datetimes are treated as UTC.
    """
    for key_path in [["@timestamp"], ["timestamp"], ["event", "created"]]:
        try:
            val = event
            for k in key_path:
                val = val[k]
            if isinstance(val, (int, float)):
                return float(val)
            iso = str(val).replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except (KeyError, TypeError, ValueError):
            continue
    return datetime.utcnow().timestamp()


def build_yaml_alert_dedup_key(
    agent_id: str,
    rule_id: str,
    event: dict,
    *,
    bucket_seconds: int = YAML_DEDUP_WINDOW_SECONDS,
) -> str:
    """Return a stable dedup key for a YAML-engine alert.

    Format: yaml:{agent_id}:{rule_id}:{content_hash}:{bucket_epoch}

    content_hash  — SHA-256 hex (first 16 chars) of
                    process.command_line → message → "" (first non-empty wins)
    bucket_epoch  — floor(event_epoch / bucket_seconds) * bucket_seconds
    """
    process = event.get("process") or {}
    raw_content = (
        process.get("command_line")
        or event.get("message")
        or ""
    )
    content_hash = hashlib.sha256(raw_content.encode()).hexdigest()[:16]
    ts = _extract_event_epoch(event)
    bucket_epoch = int(ts / bucket_seconds) * bucket_seconds
    return f"yaml:{agent_id}:{rule_id}:{content_hash}:{bucket_epoch}"


def is_duplicate_yaml_alert(dedup_key: str, db) -> bool:
    """Return True if an Alert row with this dedup_key already exists."""
    return (
        db.query(models.Alert)
        .filter(models.Alert.dedup_key == dedup_key)
        .first()
        is not None
    )


def _get_technique_id(mitre: dict) -> str:
    """Normalise MITRE technique field to a plain string ID.

    Handles both dict form {'id': 'T1059.004', ...} and legacy string form 'T1059'.
    """
    tech = mitre.get("technique", {})
    if isinstance(tech, dict):
        return tech.get("id", "")
    return str(tech) if tech else ""


def _build_event_context(event: dict) -> dict:
    """Extract key ECS fields from a normalized event for investigation evidence display.

    Returns only non-None values so the UI can render present fields and omit absent ones.
    """
    ctx = {
        "file.path":            event.get("file", {}).get("path"),
        "file.name":            event.get("file", {}).get("name"),
        "process.name":         event.get("process", {}).get("name"),
        "process.command_line": event.get("process", {}).get("command_line"),
        "process.executable":   event.get("process", {}).get("executable"),
        "user.name":            event.get("user", {}).get("name"),
        "host.name":            event.get("host", {}).get("name") or event.get("hostname"),
        "event.action":         event.get("event", {}).get("action"),
        "audit.event_id":       event.get("audit", {}).get("event_id"),
    }
    return {k: v for k, v in ctx.items() if v is not None}


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
                    if _get_technique_id(candidate.mitre) in ("T1059", "T1059.004"):
                        yaml_fired_t1059 = True
                elif candidate.matched and candidate.suppressed:
                    logger.info(f"[ACTIVE_RUNNER] SUPPRESSED match: {candidate.rule_id}")

        except Exception as e:
            logger.error(f"[ACTIVE_RUNNER] Error during YAML evaluation: {e}", exc_info=True)
            yaml_fired_t1059 = False

        # --- Correlation Engine ---
        if ENABLE_CORRELATION_ENGINE:
            self._run_correlation(normalized_event, yaml_fired_t1059)

        # --- SSH Brute Force Engine ---
        if ENABLE_SSH_BRUTEFORCE_ENGINE:
            self._run_ssh_bruteforce(normalized_event)

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
            "supporting_evidence": match.supporting_evidence,
            "optional_keys": match.optional_keys,
        }

        description = (
            f"{match.rule_name}. {match.reason}"
            f"\n\nFirst Event: [{match.first_event_process}] {match.first_event_command}"
            f"\nSecond Event: [{match.second_event_process}] {match.second_event_command}"
            f"\nTime Delta: {match.time_delta_seconds}s"
        )

        spec = AlertSpec(
            host=str(host),
            severity=match.severity.upper(),
            title=f"[{match.rule_id}] {match.rule_name}",
            description=description,
            source=match.mitre_technique,
            agent_id=match.agent_id,
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            risk_score=match.risk_score,
            mitre_tactic=match.mitre_tactic,
            mitre_technique=match.mitre_technique,
            detection_engine="CorrelationEngine",
            detection_metadata=detection_metadata,
        )
        create_alert(self.db, spec, trigger_soar=True)
        logger.info(
            f"[CORR] ALERT CREATED: {match.rule_id} on {host} "
            f"(Risk: {match.risk_score}, delta={match.time_delta_seconds}s)"
        )

    # -----------------------------------------------------------------------
    # SSH Brute Force pass
    # -----------------------------------------------------------------------

    def _run_ssh_bruteforce(self, event: Dict[str, Any]) -> None:
        """Run SSH brute force threshold detection for authentication events."""
        event_block = event.get("event") or {}
        if not isinstance(event_block, dict):
            return
        if event_block.get("category") != "authentication":
            return

        try:
            bf_engine = SSHBruteForceEngine(
                buffer=get_ssh_failure_buffer(),
                dedup=get_ssh_bf_dedup(),
                db=self.db,
            )
            match = bf_engine.evaluate(event)
        except Exception as e:
            logger.error(f"[SSH_BF] Engine error: {e}", exc_info=True)
            return

        if match:
            self._create_ssh_bruteforce_alert(event, match)

    def _create_ssh_bruteforce_alert(
        self, event: Dict[str, Any], match: SSHBruteForceMatch
    ) -> None:
        """Create a standard Alert record for an SSH brute-force threshold hit."""
        host = event.get("hostname", event.get("host", "unknown"))
        if isinstance(host, dict):
            host = host.get("name", "unknown")

        detection_metadata = {
            "rule_id": match.rule_id,
            "rule_name": match.rule_name,
            "source_ip": match.source_ip,
            "user_name": match.user_name,
            "failure_count": match.failure_count,
            "threshold": match.threshold,
            "time_window_seconds": match.time_window_seconds,
            "dedup_seconds": match.dedup_seconds,
            "match_reasons": match.match_reasons,
            "recommended_actions": [
                "Block source IP at firewall if brute-force is confirmed.",
                "Check if any login eventually succeeded from the same source IP.",
                "Review the targeted user account for signs of compromise.",
                "Enable account lockout policy if not already configured.",
                "Correlate with other auth logs for the same source IP across hosts.",
            ],
        }

        description = (
            f"{match.rule_name}. "
            f"{match.failure_count} failed SSH login(s) from {match.source_ip} "
            f"within {match.time_window_seconds}s."
        )
        if match.user_name:
            description += f" Target user(s): {match.user_name}."
        description += f"\n\nReasons: {', '.join(match.match_reasons)}"

        spec = AlertSpec(
            host=str(host),
            severity=match.severity.upper(),
            title=f"[{match.rule_id}] {match.rule_name}",
            description=description,
            source=match.mitre_technique,
            agent_id=match.agent_id,
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            risk_score=match.risk_score,
            mitre_tactic=match.mitre_tactic,
            mitre_technique=match.mitre_technique,
            detection_engine="SSHBruteForceEngine",
            detection_metadata=detection_metadata,
        )
        create_alert(self.db, spec, trigger_soar=True)
        logger.info(
            f"[SSH_BF] ALERT CREATED: {match.rule_id} on {host} "
            f"(source_ip={match.source_ip}, count={match.failure_count}, risk={match.risk_score})"
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

        # YAML dedup key — the actual duplicate check + short-circuit happens in
        # alert_service.create_alert (dedup_key is passed through on the spec).
        _agent_id = str(event.get("agent_id") or "")
        _rule_id  = str(candidate.rule_id or "")
        dedup_key = build_yaml_alert_dedup_key(_agent_id, _rule_id, event)
        # Bucket display timestamps — UTC + GMT+8; dedup logic uses UTC epoch only
        _bucket_epoch = int(_extract_event_epoch(event) / YAML_DEDUP_WINDOW_SECONDS) * YAML_DEDUP_WINDOW_SECONDS
        _bucket_time_utc  = datetime.fromtimestamp(_bucket_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        _bucket_time_gmt8 = datetime.fromtimestamp(_bucket_epoch, tz=timezone.utc).astimezone(_GMT8).isoformat()

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
            "errors": candidate.errors,
            "dedup_key": dedup_key,
            "dedup_window_seconds": YAML_DEDUP_WINDOW_SECONDS,
            "dedup_bucket_epoch_utc": _bucket_epoch,
            "dedup_bucket_time_utc": _bucket_time_utc,
            "dedup_bucket_time_gmt8": _bucket_time_gmt8,
        }
        metadata["event_context"] = _build_event_context(event)

        # Extract IDs from MITRE dictionaries if they are dicts
        tactic = mitre_info.get("tactic", "Unknown")
        if isinstance(tactic, dict):
            tactic = tactic.get("id", tactic.get("name", "Unknown"))
            
        technique = mitre_info.get("technique", "Unknown")
        if isinstance(technique, dict):
            technique = technique.get("id", technique.get("name", "Unknown"))

        spec = AlertSpec(
            host=host,
            severity=candidate.severity.upper(),
            title=f"[{candidate.rule_id}] {candidate.rule_name}",
            description=description,
            source=str(technique),
            agent_id=event.get("agent_id"),
            rule_id=candidate.rule_id,
            rule_name=candidate.rule_name,
            risk_score=candidate.risk_score,
            mitre_tactic=str(tactic),
            mitre_technique=str(technique),
            detection_engine="YAML",
            detection_metadata=metadata,
            dedup_key=dedup_key,
        )
        alert = create_alert(self.db, spec, trigger_soar=True)
        if alert is None:
            logger.info(
                f"[ACTIVE_RUNNER] DUPLICATE SKIPPED: rule={candidate.rule_id} "
                f"agent={_agent_id} dedup_key={dedup_key}"
            )
            return
        logger.info(f"[ACTIVE_RUNNER] ALERT CREATED: {candidate.rule_id} on {host} (Risk: {candidate.risk_score})")
