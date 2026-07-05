"""
test_ai_triage_queue.py — cross-alert AI triage list endpoint (v2.12.0).

Covers: newest-first ordering with alert context, status/priority filters,
pagination, status counts, and config reporting.
"""
import os
from datetime import datetime, timedelta
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, AIAlertTriage, Alert
from app.routers.ai_triage import list_triage_results, triage_config_status

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _db():
    db = _Session()
    db.query(AIAlertTriage).delete()
    db.query(Alert).delete()
    db.commit()
    return db


def _seed(db, n=3):
    alert = Alert(severity="HIGH", title="Suspicious sudo chain", host="web-01")
    db.add(alert)
    db.commit()
    base = datetime.utcnow()
    statuses = ["ok", "ok", "disabled"]
    priorities = ["P1", "P2", None]
    for i in range(n):
        db.add(AIAlertTriage(
            alert_id=alert.id, provider="gemini", model_name="gemini-2.5-flash",
            triage_status=statuses[i % 3], priority=priorities[i % 3],
            summary=f"run {i}", created_at=base + timedelta(minutes=i),
        ))
    db.commit()
    return alert


def test_list_orders_newest_first_with_alert_context():
    db = _db()
    _seed(db)
    out = list_triage_results(triage_status="", priority="", page=1, page_size=20, database=db)
    assert out["total"] == 3
    assert out["results"][0]["summary"] == "run 2"  # newest first
    assert out["results"][0]["alert_title"] == "Suspicious sudo chain"
    assert out["results"][0]["alert_severity"] == "HIGH"
    assert out["status_counts"] == {"ok": 2, "disabled": 1}
    db.close()


def test_filters_and_pagination():
    db = _db()
    _seed(db)
    out = list_triage_results(triage_status="ok", priority="", page=1, page_size=20, database=db)
    assert out["total"] == 2 and all(r["triage_status"] == "ok" for r in out["results"])

    out = list_triage_results(triage_status="", priority="P1", page=1, page_size=20, database=db)
    assert out["total"] == 1 and out["results"][0]["priority"] == "P1"

    out = list_triage_results(triage_status="", priority="", page=2, page_size=2, database=db)
    assert out["total"] == 3 and len(out["results"]) == 1 and out["page_count"] == 2
    db.close()


def test_config_status_reflects_env(monkeypatch):
    monkeypatch.setenv("AI_TRIAGE_ENABLED", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    cfg = triage_config_status()
    assert cfg["enabled"] and cfg["provider_configured"]

    monkeypatch.delenv("AI_TRIAGE_ENABLED", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    cfg = triage_config_status()
    assert not cfg["enabled"] and not cfg["provider_configured"]
