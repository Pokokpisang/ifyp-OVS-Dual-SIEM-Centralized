"""
Detection engine — YAML-only.

RuleEngine is kept as a thin wrapper so callers (collector.py,
opensearch_poller.py) require no import changes.
All detection delegates unconditionally to ActiveDetectionRunner.
DETECTION_ENGINE_MODE is intentionally ignored.
"""
import logging
from sqlalchemy.orm import Session
from .audit_parser import AuditdParser
from .active_runner import ActiveDetectionRunner
from .audit_event_aggregator import get_audit_event_aggregator

logger = logging.getLogger("detection.engine")


class RuleEngine:
    def __init__(self, db: Session):
        self.db = db

    def evaluate_raw(self, raw_log: dict):
        raw_log = AuditdParser.normalize_log(raw_log)

        aggregator = get_audit_event_aggregator()
        audit_event_id = aggregator.extract_audit_event_id(raw_log.get("message", ""))
        agent_id = raw_log.get("agent_id", "")

        if audit_event_id and agent_id:
            completed = aggregator.add_record(agent_id, audit_event_id, raw_log)
            for merged_event in completed:
                ActiveDetectionRunner(self.db).run(merged_event)
        else:
            ActiveDetectionRunner(self.db).run(raw_log)
