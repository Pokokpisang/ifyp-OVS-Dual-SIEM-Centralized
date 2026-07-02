"""
test_audit_service.py — the centralized audit helper.

Covers record_audit_event (field mapping, JSON-into-Text encoding, commit-flag
behaviour, truncation, object_id stringification) and list_audit_events filters.
"""
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.models import Base
from app.services import audit_service

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _clear(s):
    s.query(models.ActivityAudit).delete()
    s.commit()


def test_record_writes_row_with_json_details():
    s = _Session()
    _clear(s)
    row = audit_service.record_audit_event(
        s,
        actor="alice",
        action=audit_service.SOAR_APPROVE,
        object_type="alert",
        object_id=42,
        details={"playbook_id": "pb", "status": "executed"},
        commit=True,
    )
    assert row.actor == "alice"
    assert row.action == "SOAR_APPROVE"
    assert row.object_type == "alert"
    assert row.object_id == "42"  # stringified
    # details is Text holding JSON, not a dict column
    assert isinstance(row.details, str)
    assert json.loads(row.details) == {"playbook_id": "pb", "status": "executed"}
    s.close()


def test_commit_false_does_not_commit():
    s = _Session()
    _clear(s)
    audit_service.record_audit_event(
        s, actor="bob", action=audit_service.LOGOUT, commit=False
    )
    # Roll back the pending add — if commit=False truly didn't commit, the row vanishes.
    s.rollback()
    other = _Session()
    try:
        assert other.query(models.ActivityAudit).filter_by(action="LOGOUT").count() == 0
    finally:
        other.close()
    s.close()


def test_commit_true_persists_across_sessions():
    s = _Session()
    _clear(s)
    audit_service.record_audit_event(
        s, actor="bob", action=audit_service.LOGIN_SUCCESS, commit=True
    )
    other = _Session()
    try:
        assert other.query(models.ActivityAudit).filter_by(action="LOGIN_SUCCESS").count() == 1
    finally:
        other.close()
    s.close()


def test_long_values_are_truncated():
    s = _Session()
    _clear(s)
    long_actor = "x" * 5000
    row = audit_service.record_audit_event(
        s, actor=long_actor, action="TEST", details={"blob": "y" * 5000}, commit=True
    )
    assert len(row.actor) <= audit_service._MAX_VALUE_LEN + 1  # +1 for the ellipsis
    assert len(json.loads(row.details)["blob"]) <= audit_service._MAX_VALUE_LEN + 1
    s.close()


def test_none_details_stored_as_null():
    s = _Session()
    _clear(s)
    row = audit_service.record_audit_event(s, actor="a", action="TEST", commit=True)
    assert row.details is None
    s.close()


def test_list_audit_events_filters():
    s = _Session()
    _clear(s)
    audit_service.record_audit_event(s, actor="alice", action="A", object_type="alert", object_id=1, commit=True)
    audit_service.record_audit_event(s, actor="bob", action="B", object_type="agent", object_id=2, commit=True)
    audit_service.record_audit_event(s, actor="alice", action="A", object_type="alert", object_id=3, commit=True)

    assert len(audit_service.list_audit_events(s)) == 3
    assert len(audit_service.list_audit_events(s, actor="alice")) == 2
    assert len(audit_service.list_audit_events(s, action="B")) == 1
    assert len(audit_service.list_audit_events(s, object_type="agent")) == 1
    assert len(audit_service.list_audit_events(s, object_id=3)) == 1
    s.close()
