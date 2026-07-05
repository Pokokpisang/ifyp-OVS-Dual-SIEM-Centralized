"""
test_soar_actions.py — SOAR actions page backend (v2.12.0).

Covers: cross-alert pending queue contents, decision_note persistence on
approve/reject (service level), note propagation into history dicts and
audit details, and the playbook catalog serializer.
"""
import json
from datetime import datetime
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, ActivityAudit, Alert, SOARActionExecution
from app.soar.response_service import approve_action, get_history, reject_action

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _db():
    db = _Session()
    for model in (ActivityAudit, SOARActionExecution, Alert):
        db.query(model).delete()
    db.commit()
    return db


def _pending_execution(db, alert_id):
    row = SOARActionExecution(
        alert_id=alert_id,
        playbook_id="ssh_bruteforce_response",
        playbook_name="SSH Bruteforce Response",
        action_id="simulated_block_ssh_source_ip",
        action_name="Block source IP",
        action_type="simulated_block_ip",
        mode="simulation",
        status="pending_approval",
        requires_approval=True,
        executed_by="analyst:dana",
        executed_at=datetime.utcnow(),
        exec_metadata=json.dumps({"match_reasons": []}),
    )
    db.add(row)
    db.commit()
    return row


def _alert(db):
    alert = Alert(severity="HIGH", title="SSH brute force", host="edge-01")
    db.add(alert)
    db.commit()
    return alert


def test_reject_persists_note_and_audits_it():
    db = _db()
    alert = _alert(db)
    row = _pending_execution(db, alert.id)

    reject_action(alert.id, row.id, db, rejected_by="admin",
                  decision_note="scope too broad — narrowing manually")

    db.refresh(row)
    assert row.status == "rejected"
    assert row.decision_note == "scope too broad — narrowing manually"

    history = get_history(alert.id, db)
    assert history[0]["decision_note"] == "scope too broad — narrowing manually"

    audit = db.query(ActivityAudit).filter_by(action="SOAR_REJECT").first()
    assert "scope too broad" in audit.details


def test_approve_persists_note():
    db = _db()
    alert = _alert(db)
    row = _pending_execution(db, alert.id)

    # Approval executes the simulated action via the registry; patch the
    # executor to keep this a pure decision-note test.
    from app.soar import response_service as rs
    from app.soar.schemas import SOARExecutionResult
    fake = SOARExecutionResult(success=True, playbook_id=row.playbook_id, action_id=row.action_id,
                               action_type=row.action_type, mode="simulation",
                               message="[SIMULATION] ok", status="executed")
    with patch.object(rs, "execute_action", return_value=fake):
        approve_action(alert.id, row.id, db, approved_by="admin", decision_note="confirmed with client")

    db.refresh(row)
    assert row.decision_note == "confirmed with client"
    assert row.approved_by == "admin"


def test_note_truncated_to_500_chars():
    db = _db()
    alert = _alert(db)
    row = _pending_execution(db, alert.id)
    reject_action(alert.id, row.id, db, rejected_by="admin", decision_note="x" * 900)
    db.refresh(row)
    assert len(row.decision_note) == 500


def test_playbook_catalog_serialization():
    from app.routers.soar import soar_playbooks
    data = soar_playbooks()
    assert data["simulation_only"] is True
    assert len(data["playbooks"]) >= 5
    for pb in data["playbooks"]:
        assert pb["mode"] == "simulation"
        assert pb["action_count"] == len(pb["actions"])
        assert all(set(a) >= {"id", "name", "type", "requires_approval"} for a in pb["actions"])
