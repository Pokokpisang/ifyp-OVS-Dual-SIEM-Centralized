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

logger = logging.getLogger("detection.engine")


class RuleEngine:
    def __init__(self, db: Session):
        self.db = db

    def evaluate_raw(self, raw_log: dict):
        raw_log = AuditdParser.normalize_log(raw_log)
        ActiveDetectionRunner(self.db).run(raw_log)
