"""
notification_service — alert notification channels (email + webhook).

Channels are admin-configured rows (``NotificationChannel``); every send —
alert-triggered or manual test — is recorded as a ``NotificationDelivery``
row so the UI can show delivery status and failure reasons.

Design rules:
- Dispatch NEVER raises into the alerting path: a broken SMTP server must not
  break detection. Failures become ``status="failed"`` delivery rows.
- Alert-triggered dispatch runs on a daemon thread with its own DB session
  (``dispatch_async``) so agent-facing ingestion endpoints are not delayed
  by SMTP/webhook latency.
- SMTP settings come from env (SMTP_HOST/PORT/USER/PASSWORD/FROM — see
  .env.example); webhook channels need no server-side config.
"""
import logging
import os
import smtplib
import threading
from datetime import datetime
from email.message import EmailMessage
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models

logger = logging.getLogger("services.notifications")

CHANNEL_TYPES = ("email", "webhook")
SEVERITY_CHOICES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Alert rows use a mix of severity spellings (HIGH/MED/LOW from detection,
# MEDIUM/LOW from metric health rules); rank them on one scale.
_SEVERITY_RANK = {"LOW": 1, "MED": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEND_TIMEOUT_SECONDS = 10


def severity_rank(severity: Optional[str]) -> int:
    return _SEVERITY_RANK.get((severity or "").upper(), 2)


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST"))


def validate_channel(channel_type: str, target: str, min_severity: str) -> Optional[str]:
    """Return an error string for invalid channel input, or None if valid."""
    if channel_type not in CHANNEL_TYPES:
        return f"channel_type must be one of {CHANNEL_TYPES}"
    if min_severity not in SEVERITY_CHOICES:
        return f"min_severity must be one of {SEVERITY_CHOICES}"
    if not target or not target.strip():
        return "target is required"
    if channel_type == "email" and ("@" not in target or " " in target.strip()):
        return "target must be an email address"
    if channel_type == "webhook":
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return "target must be an http(s) URL"
    return None


# ---------------------------------------------------------------------------
# Senders — raise on failure; callers convert failures into delivery rows.
# ---------------------------------------------------------------------------

def _send_email(target: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST")
    if not host:
        raise RuntimeError("SMTP not configured (set SMTP_HOST in api/.env)")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", user or "ovs-alerts@localhost")

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = target
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=_SEND_TIMEOUT_SECONDS) as smtp:
        smtp.ehlo()
        try:
            smtp.starttls()
            smtp.ehlo()
        except smtplib.SMTPNotSupportedError:
            pass  # plaintext relay (e.g. local mailhog)
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)


def _send_webhook(target: str, payload: dict) -> None:
    resp = httpx.post(target, json=payload, timeout=_SEND_TIMEOUT_SECONDS)
    if resp.status_code >= 400:
        raise RuntimeError(f"webhook returned HTTP {resp.status_code}")


def _alert_payload(alert: models.Alert) -> Tuple[str, str, dict]:
    """(subject, email body, webhook JSON) for one alert."""
    subject = f"[OVS {alert.severity}] {alert.title}"
    body = (
        f"OVS security alert #{alert.id}\n"
        f"Severity : {alert.severity}\n"
        f"Host     : {alert.host or '-'}\n"
        f"Rule     : {alert.rule_name or alert.rule_id or '-'}\n"
        f"MITRE    : {alert.mitre_technique or alert.source or '-'}\n"
        f"Engine   : {alert.detection_engine or '-'}\n"
        f"Time     : {alert.timestamp}\n\n"
        f"{alert.description or ''}\n\n"
        f"Investigate: /alerts/{alert.id}/investigation\n"
    )
    payload = {
        "source": "ovs",
        "event": "alert.created",
        "alert_id": alert.id,
        "severity": alert.severity,
        "title": alert.title,
        "host": alert.host,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "mitre_technique": alert.mitre_technique,
        "detection_engine": alert.detection_engine,
        "risk_score": alert.risk_score,
        "timestamp": str(alert.timestamp),
        "investigation_path": f"/alerts/{alert.id}/investigation",
    }
    return subject, body, payload


def _deliver(db: Session, channel: models.NotificationChannel, *, subject: str,
             body: str, payload: dict, alert_id: Optional[int]) -> models.NotificationDelivery:
    """Send via one channel and record the outcome. Never raises."""
    status, error = "sent", None
    try:
        if channel.channel_type == "email":
            _send_email(channel.target, subject, body)
        else:
            _send_webhook(channel.target, payload)
    except Exception as exc:  # noqa: BLE001 — any send failure becomes a log row
        status, error = "failed", str(exc)[:500]
        logger.warning("[NOTIFY] %s via %s failed: %s", subject, channel.name, exc)

    row = models.NotificationDelivery(
        channel_id=channel.id,
        channel_name=channel.name,
        channel_type=channel.channel_type,
        target=channel.target,
        alert_id=alert_id,
        subject=subject,
        status=status,
        error_message=error,
        created_at=datetime.utcnow(),
    )
    db.add(row)
    return row


def dispatch_for_alert(db: Session, alert: models.Alert) -> List[models.NotificationDelivery]:
    """Send the alert through every enabled channel whose min_severity matches.

    Records one delivery row per channel and commits. Never raises.
    """
    try:
        channels = (
            db.query(models.NotificationChannel)
            .filter(models.NotificationChannel.enabled == True)  # noqa: E712
            .all()
        )
        matching = [c for c in channels if severity_rank(alert.severity) >= severity_rank(c.min_severity)]
        if not matching:
            return []
        subject, body, payload = _alert_payload(alert)
        rows = [
            _deliver(db, c, subject=subject, body=body, payload=payload, alert_id=alert.id)
            for c in matching
        ]
        db.commit()
        return rows
    except Exception:  # noqa: BLE001
        logger.exception("[NOTIFY] dispatch_for_alert failed for alert %s", getattr(alert, "id", "?"))
        db.rollback()
        return []


def dispatch_async(alert_id: int) -> None:
    """Fire-and-forget dispatch on a daemon thread with its own session, so
    agent-facing ingestion never waits on SMTP/webhook latency."""

    def _run():
        from .. import db as db_module
        session = db_module.SessionLocal()
        try:
            alert = session.query(models.Alert).filter(models.Alert.id == alert_id).first()
            if alert:
                dispatch_for_alert(session, alert)
        finally:
            session.close()

    threading.Thread(target=_run, daemon=True, name=f"notify-alert-{alert_id}").start()


def send_test(db: Session, channel: models.NotificationChannel) -> models.NotificationDelivery:
    """Send a sample notification through one channel; records + commits the outcome."""
    subject = "[OVS TEST] Notification channel test"
    body = (
        f"This is a test notification from OVS.\n"
        f"Channel  : {channel.name} ({channel.channel_type})\n"
        f"If you can read this, the channel is working.\n"
    )
    payload = {"source": "ovs", "event": "channel.test", "channel": channel.name}
    row = _deliver(db, channel, subject=subject, body=body, payload=payload, alert_id=None)
    db.commit()
    return row


def list_recent_deliveries(db: Session, limit: int = 50) -> List[models.NotificationDelivery]:
    return (
        db.query(models.NotificationDelivery)
        .order_by(desc(models.NotificationDelivery.created_at), desc(models.NotificationDelivery.id))
        .limit(limit)
        .all()
    )
