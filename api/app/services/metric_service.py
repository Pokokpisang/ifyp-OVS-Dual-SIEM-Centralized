"""
metric_service — system-metrics summarisation and health-rule alerting.

Extracted from routers/api_metrics.py so the ingest route stays a thin HTTP
handler. ``evaluate_health_rules`` owns the threshold + cooldown logic and
delegates persistence to alert_service (health alerts never trigger SOAR).
"""
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models
from .alert_service import AlertSpec, create_alert


def compute_metrics_summary(db: Session, host: Optional[str] = None) -> dict:
    """Latest CPU/RAM plus a network rate derived from the two most recent
    samples for the host. Returns {} when no metric exists."""
    query = db.query(models.Metric)
    if host:
        query = query.filter(models.Metric.host == host)
    latest = query.order_by(desc(models.Metric.timestamp)).first()

    if not latest:
        return {}

    prev = (
        db.query(models.Metric)
        .filter(
            models.Metric.host == latest.host,
            models.Metric.timestamp < latest.timestamp,
        )
        .order_by(desc(models.Metric.timestamp))
        .first()
    )

    net_in_rate = 0.0
    net_out_rate = 0.0
    if prev:
        time_diff = (latest.timestamp - prev.timestamp).total_seconds()
        if time_diff > 0:
            net_in_rate = (float(latest.net_in_bytes) - float(prev.net_in_bytes)) / time_diff
            net_out_rate = (float(latest.net_out_bytes) - float(prev.net_out_bytes)) / time_diff

    return {
        "cpu_percent": float(latest.cpu_percent),
        "ram_percent": float(latest.ram_percent),
        "net_in_rate": max(0, net_in_rate),   # avoid negatives after a counter reset
        "net_out_rate": max(0, net_out_rate),
    }


def _observed_value(db: Session, metric: models.MetricCreate, rule) -> tuple:
    """Return (observed_value, unit) for a rule against the incoming metric."""
    if rule.metric_name == "cpu":
        return float(metric.cpu_percent), "%"
    if rule.metric_name == "ram":
        return float(metric.ram_percent), "%"
    if rule.metric_name == "net_in":
        return compute_metrics_summary(db, host=metric.host).get("net_in_rate", 0.0), "B/s"
    if rule.metric_name == "net_out":
        return compute_metrics_summary(db, host=metric.host).get("net_out_rate", 0.0), "B/s"
    return 0.0, "%"


def _threshold_breached(observed_value: float, operator: str, threshold: float) -> bool:
    if operator == ">":
        return observed_value > threshold
    if operator == "<":
        return observed_value < threshold
    return False


def evaluate_health_rules(
    db: Session,
    metric: models.MetricCreate,
    agent_meta: Optional[dict],
) -> List[models.Alert]:
    """Evaluate all enabled SystemHealthRule rows against *metric*.

    Fires at most one alert per breached rule, subject to a 5-minute per-rule
    cooldown. Health alerts do not trigger SOAR. Returns the alerts created.
    """
    created: List[models.Alert] = []
    health_rules = (
        db.query(models.SystemHealthRule)
        .filter(models.SystemHealthRule.enabled == True)  # noqa: E712
        .all()
    )

    for rule in health_rules:
        observed_value, unit = _observed_value(db, metric, rule)
        if not _threshold_breached(observed_value, rule.operator, rule.threshold_value):
            continue

        cooldown_period = datetime.utcnow() - timedelta(minutes=5)
        recent_alert = (
            db.query(models.Alert)
            .filter(
                models.Alert.host == metric.host,
                models.Alert.rule_id == rule.rule_id,
                models.Alert.timestamp > cooldown_period,
            )
            .first()
        )
        if recent_alert:
            continue

        metadata = {
            "engine": rule.detection_engine,
            "metric": rule.metric_name,
            "threshold": rule.threshold_value,
            "observed_value": round(observed_value, 2),
            "unit": unit,
        }
        spec = AlertSpec(
            host=metric.host,
            severity=rule.severity,
            title=rule.rule_name,
            description=(
                f"{rule.rule_name}: {rule.metric_name} {rule.operator} "
                f"{rule.threshold_value}{unit} (Observed: {round(observed_value, 2)}{unit})"
            ),
            source=None,  # Not MITRE
            agent_id=agent_meta["agent_id"] if agent_meta else None,
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            risk_score=20,
            detection_engine=rule.detection_engine,
            detection_metadata=metadata,
        )
        # commit=False so rule.last_triggered lands in the same transaction.
        alert = create_alert(db, spec, trigger_soar=False, commit=False)
        rule.last_triggered = datetime.utcnow()
        db.commit()
        if alert is not None:
            created.append(alert)
            # commit=False skips create_alert's own dispatch; notify here
            # once the alert id is committed. Threaded, never blocks ingestion.
            from .notification_service import dispatch_async
            dispatch_async(alert.id)

    return created
