"""
test_agent_delete_cleanup.py — deleting an agent drops its (high-volume,
disposable) Metric rows but keeps Logs, Alerts, and the AgentRecord itself.
"""
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.models import Base
from app.services.agent_service import create_agent, delete_agent_by_id

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _seed_host_data(s, host):
    s.add(models.Metric(timestamp=datetime.utcnow(), host=host, cpu_percent="10.0",
                        ram_percent="20.0", net_in_bytes="1", net_out_bytes="2"))
    s.add(models.Log(timestamp=datetime.utcnow(), host=host, log_type="auditd", message="m"))
    s.add(models.Alert(timestamp=datetime.utcnow(), host=host, severity="HIGH", title="t"))
    s.commit()


def _count(s, model, host):
    return s.query(model).filter(model.host == host).count()


def test_delete_removes_metrics_keeps_logs_alerts_and_record():
    s = _Session()
    for m in (models.Metric, models.Log, models.Alert, models.AgentRecord):
        s.query(m).delete()
    s.commit()

    agent, _ = create_agent(
        agent_name="del-1", group="g", tags="", os_type="Linux",
        distribution="Ubuntu", architecture="x86_64",
        enable_logs=True, enable_fim=False, enable_metrics=True, db=s,
    )
    agent.hostname = "del-1"
    s.commit()
    _seed_host_data(s, "del-1")
    # sanity: data present before delete
    assert _count(s, models.Metric, "del-1") == 1
    assert _count(s, models.Log, "del-1") == 1
    assert _count(s, models.Alert, "del-1") == 1

    assert delete_agent_by_id(agent.agent_id, s) is True

    # metrics gone; logs + alerts preserved
    assert _count(s, models.Metric, "del-1") == 0
    assert _count(s, models.Log, "del-1") == 1
    assert _count(s, models.Alert, "del-1") == 1

    # AgentRecord kept, soft-deleted (still available for lifecycle history)
    rec = s.query(models.AgentRecord).filter_by(agent_id=agent.agent_id).first()
    assert rec is not None
    assert rec.is_deleted is True
    assert rec.lifecycle_status == "deleted"
    s.close()


def test_delete_missing_agent_returns_false():
    s = _Session()
    assert delete_agent_by_id("no-such-id", s) is False
    s.close()
