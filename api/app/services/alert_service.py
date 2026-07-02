"""
alert_service — the single place that turns a detection result into a
persisted ``models.Alert``.

Before this module, four call sites (the YAML, correlation and SSH brute-force
detection engines, plus the system-health metric router) each hand-built a
``models.Alert(...)`` with the same field block, JSON-encoded the metadata, and
independently decided whether to fire the SOAR auto-run. ``create_alert``
centralises that so every alert is shaped and side-effected consistently.
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from .. import models
from ..soar.auto_runner import trigger_soar_auto_run_for_alert

logger = logging.getLogger("services.alert")


@dataclass
class AlertSpec:
    """A detection-engine-agnostic description of an alert to persist.

    ``severity`` is stored verbatim — callers pass the casing they want
    (detection engines upper-case it; health rules keep the rule's own value).
    ``detection_metadata`` is a plain dict; the service JSON-encodes it.
    """

    host: str
    severity: str
    title: str
    description: str
    detection_engine: str
    detection_metadata: dict = field(default_factory=dict)
    source: Optional[str] = None
    agent_id: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    risk_score: Optional[int] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    dedup_key: Optional[str] = None
    timestamp: Optional[datetime] = None


def alert_exists_with_dedup_key(db: Session, dedup_key: str) -> bool:
    """Return True if an Alert row already carries this dedup_key."""
    return (
        db.query(models.Alert)
        .filter(models.Alert.dedup_key == dedup_key)
        .first()
        is not None
    )


def create_alert(
    db: Session,
    spec: AlertSpec,
    *,
    trigger_soar: bool = True,
    commit: bool = True,
) -> Optional[models.Alert]:
    """Persist an Alert from *spec*.

    - If ``spec.dedup_key`` is set and an Alert with that key already exists,
      nothing is written and ``None`` is returned.
    - When ``commit`` is True the row is committed; SOAR auto-run is then fired
      when ``trigger_soar`` is True (it needs the committed ``alert.id``).
    - When ``commit`` is False the caller owns the commit (e.g. so it can be
      batched with other writes in the same transaction); SOAR is not fired.
    """
    if spec.dedup_key and alert_exists_with_dedup_key(db, spec.dedup_key):
        logger.info(
            "[ALERT] Duplicate skipped: rule=%s agent=%s dedup_key=%s",
            spec.rule_id, spec.agent_id, spec.dedup_key,
        )
        return None

    alert = models.Alert(
        timestamp=spec.timestamp or datetime.utcnow(),
        host=spec.host,
        severity=spec.severity,
        title=spec.title,
        description=spec.description,
        source=spec.source,
        agent_id=spec.agent_id,
        rule_id=spec.rule_id,
        rule_name=spec.rule_name,
        risk_score=spec.risk_score,
        mitre_tactic=spec.mitre_tactic,
        mitre_technique=spec.mitre_technique,
        detection_engine=spec.detection_engine,
        detection_metadata=json.dumps(spec.detection_metadata),
        dedup_key=spec.dedup_key,
    )
    db.add(alert)

    if commit:
        db.commit()
        logger.info(
            "[ALERT] Created: rule=%s host=%s engine=%s risk=%s",
            spec.rule_id, spec.host, spec.detection_engine, spec.risk_score,
        )
        if trigger_soar:
            trigger_soar_auto_run_for_alert(alert.id, db)

    return alert


def get_actor_username(request: Request, default: str = "unknown") -> str:
    """Return the authenticated username from request state, or *default*."""
    user = getattr(request.state, "user", None) or {}
    return user.get("username", default)
