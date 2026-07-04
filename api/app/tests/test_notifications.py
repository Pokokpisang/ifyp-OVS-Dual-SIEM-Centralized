"""
test_notifications.py — notification channels + dispatch (v2.11.0).

Covers: channel validation, severity gating, disabled-channel skip,
delivery rows for success/failure, unconfigured-SMTP failure, test sends.
Senders are mocked — no network traffic.
"""
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Alert, NotificationChannel, NotificationDelivery
from app.services import notification_service as ns

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _db():
    db = _Session()
    db.query(NotificationDelivery).delete()
    db.query(NotificationChannel).delete()
    db.query(Alert).delete()
    db.commit()
    return db


def _channel(db, *, name="ch", channel_type="webhook", target="https://hooks.example.com/x",
             min_severity="HIGH", enabled=True):
    ch = NotificationChannel(name=name, channel_type=channel_type, target=target,
                             min_severity=min_severity, enabled=enabled)
    db.add(ch)
    db.commit()
    return ch


def _alert(db, severity="HIGH"):
    alert = Alert(severity=severity, title=f"{severity} test alert", host="web-01")
    db.add(alert)
    db.commit()
    return alert


def test_validate_channel():
    assert ns.validate_channel("email", "soc@example.com", "HIGH") is None
    assert ns.validate_channel("webhook", "https://hooks.example.com/a", "LOW") is None
    assert ns.validate_channel("sms", "x", "HIGH") is not None          # bad type
    assert ns.validate_channel("email", "not-an-email", "HIGH") is not None
    assert ns.validate_channel("webhook", "ftp://x/y", "HIGH") is not None   # bad scheme
    assert ns.validate_channel("webhook", "javascript:alert(1)", "HIGH") is not None
    assert ns.validate_channel("email", "a@b.c", "SEVERE") is not None  # bad severity
    assert ns.validate_channel("email", "", "HIGH") is not None


def test_severity_rank_handles_spelling_variants():
    assert ns.severity_rank("MED") == ns.severity_rank("MEDIUM")
    assert ns.severity_rank("high") == ns.severity_rank("HIGH")
    assert ns.severity_rank("CRITICAL") > ns.severity_rank("HIGH") > ns.severity_rank("LOW")
    assert ns.severity_rank(None) == ns.severity_rank("MEDIUM")  # unknown → medium


def test_dispatch_severity_gating():
    db = _db()
    _channel(db, name="high-only", min_severity="HIGH")
    with patch.object(ns, "_send_webhook") as send:
        rows = ns.dispatch_for_alert(db, _alert(db, "MED"))
        assert rows == [] and send.call_count == 0
        rows = ns.dispatch_for_alert(db, _alert(db, "HIGH"))
        assert len(rows) == 1 and send.call_count == 1
        rows = ns.dispatch_for_alert(db, _alert(db, "CRITICAL"))
        assert len(rows) == 1 and send.call_count == 2
    db.close()


def test_dispatch_skips_disabled_channels():
    db = _db()
    _channel(db, name="off", enabled=False, min_severity="LOW")
    with patch.object(ns, "_send_webhook") as send:
        assert ns.dispatch_for_alert(db, _alert(db, "CRITICAL")) == []
        assert send.call_count == 0
    db.close()


def test_dispatch_records_sent_and_failed_rows():
    db = _db()
    _channel(db, name="works", target="https://ok.example.com/h", min_severity="LOW")
    _channel(db, name="broken", target="https://down.example.com/h", min_severity="LOW")

    def _flaky(target, payload):
        if "down" in target:
            raise RuntimeError("connection refused")

    with patch.object(ns, "_send_webhook", side_effect=_flaky):
        alert = _alert(db, "HIGH")
        rows = ns.dispatch_for_alert(db, alert)

    by_name = {r.channel_name: r for r in rows}
    assert by_name["works"].status == "sent" and by_name["works"].alert_id == alert.id
    assert by_name["broken"].status == "failed"
    assert "connection refused" in by_name["broken"].error_message
    assert db.query(NotificationDelivery).count() == 2  # committed
    db.close()


def test_dispatch_never_raises_on_sender_crash():
    db = _db()
    _channel(db, min_severity="LOW")
    with patch.object(ns, "_send_webhook", side_effect=Exception("boom")):
        rows = ns.dispatch_for_alert(db, _alert(db))  # must not raise
    assert rows[0].status == "failed"
    db.close()


def test_email_without_smtp_config_records_failure(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    db = _db()
    ch = _channel(db, channel_type="email", target="soc@example.com", min_severity="LOW")
    row = ns.send_test(db, ch)
    assert row.status == "failed"
    assert "SMTP not configured" in row.error_message
    assert row.alert_id is None  # test sends carry no alert
    db.close()


def test_send_test_success_records_row():
    db = _db()
    ch = _channel(db)
    with patch.object(ns, "_send_webhook"):
        row = ns.send_test(db, ch)
    assert row.status == "sent" and row.alert_id is None
    assert db.query(NotificationDelivery).count() == 1
    db.close()
