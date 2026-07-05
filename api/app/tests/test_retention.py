"""
test_retention.py — data-retention sweep (v2.13.0).

Covers: cutoff correctness per data class, unlimited-by-default semantics
(unset/invalid/zero envs), independence of the two windows, audit evidence
on real deletions, and silence on no-op sweeps.
"""
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, ActivityAudit, Log, Metric
from app.services.retention_service import get_retention_policy, run_retention_sweep

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _db():
    db = _Session()
    for model in (ActivityAudit, Log, Metric):
        db.query(model).delete()
    db.commit()
    return db


def _seed(db):
    now = datetime.utcnow()
    db.add(Log(timestamp=now - timedelta(days=100), host="h", log_type="syslog", message="old log"))
    db.add(Log(timestamp=now - timedelta(days=1), host="h", log_type="syslog", message="fresh log"))
    db.add(Metric(timestamp=now - timedelta(days=40), host="h", cpu_percent=1, ram_percent=1,
                  net_in_bytes=0, net_out_bytes=0))
    db.add(Metric(timestamp=now - timedelta(hours=1), host="h", cpu_percent=1, ram_percent=1,
                  net_in_bytes=0, net_out_bytes=0))
    db.commit()


def test_unset_env_means_unlimited(monkeypatch):
    monkeypatch.delenv("LOG_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("METRICS_RETENTION_DAYS", raising=False)
    db = _db()
    _seed(db)
    deleted = run_retention_sweep(db)
    assert deleted == {"logs": 0, "metrics": 0}
    assert db.query(Log).count() == 2 and db.query(Metric).count() == 2
    assert db.query(ActivityAudit).count() == 0  # no-op sweeps leave no audit noise
    db.close()


def test_invalid_and_zero_envs_are_unlimited(monkeypatch):
    monkeypatch.setenv("LOG_RETENTION_DAYS", "ninety")
    monkeypatch.setenv("METRICS_RETENTION_DAYS", "0")
    assert get_retention_policy() == {"log_days": None, "metrics_days": None}


def test_sweep_deletes_only_past_cutoff_and_audits(monkeypatch):
    monkeypatch.setenv("LOG_RETENTION_DAYS", "90")
    monkeypatch.setenv("METRICS_RETENTION_DAYS", "30")
    db = _db()
    _seed(db)
    deleted = run_retention_sweep(db)
    assert deleted == {"logs": 1, "metrics": 1}
    assert db.query(Log).one().message == "fresh log"
    assert db.query(Metric).count() == 1

    audit = db.query(ActivityAudit).filter_by(action="DATA_RETENTION_APPLIED").one()
    assert audit.actor == "system:retention"
    assert '"logs_deleted": 1' in audit.details and '"metrics_deleted": 1' in audit.details

    # Second sweep: nothing left to delete, no extra audit rows
    assert run_retention_sweep(db) == {"logs": 0, "metrics": 0}
    assert db.query(ActivityAudit).filter_by(action="DATA_RETENTION_APPLIED").count() == 1
    db.close()


def test_windows_are_independent(monkeypatch):
    monkeypatch.setenv("LOG_RETENTION_DAYS", "90")
    monkeypatch.delenv("METRICS_RETENTION_DAYS", raising=False)
    db = _db()
    _seed(db)
    deleted = run_retention_sweep(db)
    assert deleted == {"logs": 1, "metrics": 0}
    assert db.query(Metric).count() == 2  # metrics untouched without a window
    db.close()
