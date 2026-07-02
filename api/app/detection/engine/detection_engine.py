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
from .process_cache import enrich_parent_name

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
                # Resolve parent name on the fully-merged event (SYSCALL ppid +
                # EXECVE comm may arrive as separate fragments).
                enrich_parent_name(merged_event)
                ActiveDetectionRunner(self.db).run(merged_event)
        else:
            enrich_parent_name(raw_log)
            ActiveDetectionRunner(self.db).run(raw_log)
