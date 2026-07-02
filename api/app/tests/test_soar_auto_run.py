"""
test_soar_auto_run.py — auto_run_for_alert idempotency, approval gating, and
mode gating.

These exercise the real playbook loader + matcher + executor against an
in-memory DB, proving:
  1. Repeated auto-runs of an auto-runnable playbook create exactly one
     SOARActionExecution (the dedup guard now matches status="executed").
  2. Approval-required playbooks are never auto-executed (stay analyst-controlled).
  3. Manual mode (the default) is a no-op.
"""
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.models import Base
from app.services.settings_service import set_setting
from app.soar.response_service import auto_run_for_alert

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _clear(s):
    for model in (models.SOARActionExecution, models.SystemSetting, models.Alert):
        s.query(model).delete()
    s.commit()


def _seed_alert(s, *, technique: str, rule_name: str = "Detected rule") -> int:
    alert = models.Alert(
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        host="vps-1",
        severity="high",
        title=f"[{technique}] test",
        description="test alert",
        source=technique,
        rule_id="rule-x",
        rule_name=rule_name,
        risk_score=55,
        mitre_technique=technique,
        detection_engine="YAML",
    )
    s.add(alert)
    s.commit()
    return alert.id


def _executions(s, alert_id):
    return s.query(models.SOARActionExecution).filter_by(alert_id=alert_id).all()


def test_auto_run_is_idempotent_for_autorunnable_playbook():
    """T1543 review playbook is auto_run_allowed + requires_approval=False.
    Two auto-runs must yield exactly one execution row."""
    s = _Session()
    _clear(s)
    set_setting(s, "soar_execution_mode", "automatic")
    alert_id = _seed_alert(s, technique="T1543.002")

    auto_run_for_alert(alert_id, s)
    auto_run_for_alert(alert_id, s)

    rows = _executions(s, alert_id)
    assert len(rows) == 1, f"expected 1 execution, got {len(rows)}"
    assert rows[0].status == "executed"
    s.close()


def test_approval_required_playbook_not_auto_executed():
    """T1059 investigation playbook is requires_approval + auto_run_allowed=False.
    Auto-run must skip it entirely (no execution row created)."""
    s = _Session()
    _clear(s)
    set_setting(s, "soar_execution_mode", "automatic")
    alert_id = _seed_alert(s, technique="T1059.004")

    result = auto_run_for_alert(alert_id, s)

    assert result["executed_count"] == 0
    assert _executions(s, alert_id) == []
    s.close()


def test_manual_mode_is_a_no_op():
    """Default (manual) SOAR mode: auto-run does nothing and writes nothing."""
    s = _Session()
    _clear(s)
    # no setting seeded → defaults to "manual"
    alert_id = _seed_alert(s, technique="T1543.002")

    result = auto_run_for_alert(alert_id, s)

    assert result["executed_count"] == 0
    assert _executions(s, alert_id) == []
    s.close()
