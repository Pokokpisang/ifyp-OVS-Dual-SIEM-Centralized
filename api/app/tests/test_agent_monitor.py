"""
test_agent_monitor.py — agent dead-silence detection (v2.11.0).

Covers: silence detection past the env threshold, one-alert-per-episode
dedup, re-alerting after recovery, skip rules (pending / deleted /
never-seen / fresh agents), and threshold env override.
"""
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, AgentRecord, Alert
from app.services import agent_monitor

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _db():
    db = _Session()
    db.query(Alert).delete()
    db.query(AgentRecord).delete()
    db.commit()
    return db


def _agent(db, *, name="web-01", status="active", last_seen_minutes_ago=None,
           is_deleted=False):
    agent = AgentRecord(
        agent_name=name,
        agent_id=str(uuid.uuid4()),
        hostname=f"{name}.example.lab",
        status=status,
        is_deleted=is_deleted,
        last_seen=(datetime.utcnow() - timedelta(minutes=last_seen_minutes_ago))
        if last_seen_minutes_ago is not None else None,
    )
    db.add(agent)
    db.commit()
    return agent


def _sweep(db):
    # dispatch_async would open the app's real SessionLocal on a thread —
    # irrelevant to these tests, so silence it.
    with patch("app.services.notification_service.dispatch_async"):
        return agent_monitor.check_silent_agents(db)


def test_silent_agent_creates_one_alert():
    db = _db()
    agent = _agent(db, last_seen_minutes_ago=30)
    created = _sweep(db)
    assert len(created) == 1
    alert = created[0]
    assert alert.severity == "HIGH"
    assert alert.detection_engine == "AgentMonitor"
    assert alert.agent_id == agent.agent_id
    assert agent.agent_name in alert.title
    db.close()


def test_repeated_sweeps_do_not_realert_same_episode():
    db = _db()
    _agent(db, last_seen_minutes_ago=30)
    assert len(_sweep(db)) == 1
    assert _sweep(db) == []  # same last_seen → same dedup key → skipped
    assert db.query(Alert).count() == 1
    db.close()


def test_recovery_then_new_silence_alerts_again():
    db = _db()
    agent = _agent(db, last_seen_minutes_ago=30)
    assert len(_sweep(db)) == 1

    # Agent heartbeats (recovers), then goes silent again later.
    agent.last_seen = datetime.utcnow()
    db.commit()
    assert _sweep(db) == []  # fresh heartbeat — not silent

    agent.last_seen = datetime.utcnow() - timedelta(minutes=45)
    db.commit()
    assert len(_sweep(db)) == 1  # new episode, new dedup key
    assert db.query(Alert).count() == 2
    db.close()


def test_skips_pending_deleted_neverseen_and_fresh_agents():
    db = _db()
    _agent(db, name="pending", status="pending", last_seen_minutes_ago=99)
    _agent(db, name="deleted", is_deleted=True, last_seen_minutes_ago=99)
    _agent(db, name="never-seen", last_seen_minutes_ago=None)
    _agent(db, name="fresh", last_seen_minutes_ago=0)
    assert _sweep(db) == []
    db.close()


def test_threshold_env_override(monkeypatch):
    db = _db()
    _agent(db, name="borderline", last_seen_minutes_ago=8)

    monkeypatch.setenv("AGENT_SILENCE_THRESHOLD_MINUTES", "10")
    assert _sweep(db) == []  # 8 min < 10 min threshold

    monkeypatch.setenv("AGENT_SILENCE_THRESHOLD_MINUTES", "5")
    created = _sweep(db)
    assert len(created) == 1  # 8 min > 5 min threshold
    assert "threshold: 5 min" in created[0].description
    db.close()


def test_invalid_threshold_falls_back_to_default(monkeypatch):
    from app.services.agent_service import get_offline_threshold_minutes, OFFLINE_THRESHOLD_MINUTES
    monkeypatch.setenv("AGENT_SILENCE_THRESHOLD_MINUTES", "not-a-number")
    assert get_offline_threshold_minutes() == OFFLINE_THRESHOLD_MINUTES
    monkeypatch.setenv("AGENT_SILENCE_THRESHOLD_MINUTES", "0")
    assert get_offline_threshold_minutes() == 1  # clamped to minimum
