"""
test_audit_trail.py — Audit Trail service layer (v2.10.0).

Covers: secret scrubbing on write + read, source_ip persistence, category
mapping, result derivation, filtered/paginated queries, and KPI summary.
"""
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, ActivityAudit
from app.services import audit_service

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _clear(db):
    db.query(ActivityAudit).delete()
    db.commit()


def _seed(db):
    """A small mixed event set."""
    audit_service.record_audit_event(
        db, actor="admin", action=audit_service.LOGIN_FAILURE,
        source_ip="203.0.113.7", details={"reason": "invalid_credentials"},
    )
    audit_service.record_audit_event(
        db, actor="admin", action=audit_service.AGENT_KEY_ROTATED,
        object_type="agent", object_id="ag-7", source_ip="10.0.0.5",
        details={"agent_id": "ag-7", "new_key": "supersecretvalue"},
    )
    audit_service.record_audit_event(
        db, actor="analyst01", action=audit_service.SOAR_RUN,
        object_type="alert", object_id=42, source_ip="10.0.0.9",
        details={"playbook_id": "pb-1", "status": "pending_approval"},
    )
    audit_service.record_audit_event(
        db, actor="admin", action=audit_service.SYSTEM_CONFIG_CHANGED,
        object_type="system", object_id="soar_execution_mode", source_ip="10.0.0.5",
        details={"setting": "soar_execution_mode", "from": "manual", "to": "automatic"},
    )
    db.commit()


def test_write_scrub_redacts_secretlike_keys():
    db = _Session()
    _clear(db)
    row = audit_service.record_audit_event(
        db, actor="admin", action=audit_service.AGENT_KEY_ROTATED,
        details={"new_key": "raw-secret", "install_token": "tok", "reason": "reinstall"},
        commit=True,
    )
    assert "raw-secret" not in (row.details or "")
    assert "tok\"" not in (row.details or "")
    assert audit_service.REDACTED in row.details
    assert "reinstall" in row.details  # non-secret keys survive
    db.close()


def test_source_ip_persisted():
    db = _Session()
    _clear(db)
    row = audit_service.record_audit_event(
        db, actor="admin", action=audit_service.LOGIN_SUCCESS,
        source_ip="198.51.100.1", commit=True,
    )
    assert row.source_ip == "198.51.100.1"
    db.close()


def test_event_to_dict_result_and_sensitive():
    db = _Session()
    _clear(db)
    _seed(db)
    rows, _ = audit_service.query_audit_events(db, page=1, page_size=50)
    by_action = {audit_service.event_to_dict(r)["action"]: audit_service.event_to_dict(r) for r in rows}

    assert by_action["LOGIN_FAILURE"]["result"] == "Failed"
    assert by_action["LOGIN_FAILURE"]["result_tone"] == "crit"
    assert by_action["LOGIN_FAILURE"]["category"] == "Authentication"
    assert by_action["SOAR_RUN"]["result"] == "Queued"  # pending_approval
    assert by_action["SYSTEM_CONFIG_CHANGED"]["result"] == "Updated"

    rotated = by_action["AGENT_KEY_ROTATED"]
    assert rotated["sensitive"] is True
    detail_map = dict(rotated["details"])
    assert detail_map["new_key"] == audit_service.REDACTED
    db.close()


def test_query_filters_and_pagination():
    db = _Session()
    _clear(db)
    _seed(db)

    rows, total = audit_service.query_audit_events(db, category="SOAR")
    assert total == 1 and rows[0].action == "SOAR_RUN"

    rows, total = audit_service.query_audit_events(db, actor="admin")
    assert total == 3

    rows, total = audit_service.query_audit_events(db, q="pending_approval")
    assert total == 1

    rows, total = audit_service.query_audit_events(db, object_id="ag-")
    assert total == 1 and rows[0].object_id == "ag-7"

    rows, total = audit_service.query_audit_events(db, page=1, page_size=2)
    assert total == 4 and len(rows) == 2
    rows2, _ = audit_service.query_audit_events(db, page=2, page_size=2)
    assert len(rows2) == 2
    assert {r.id for r in rows}.isdisjoint({r.id for r in rows2})
    db.close()


def test_since_filter_excludes_old_rows():
    db = _Session()
    _clear(db)
    _seed(db)
    old = db.query(ActivityAudit).filter_by(action="LOGIN_FAILURE").first()
    old.timestamp_utc = datetime.utcnow() - timedelta(days=10)
    db.commit()

    since = audit_service.range_to_since("7d")
    _, total = audit_service.query_audit_events(db, since=since)
    assert total == 3
    assert audit_service.range_to_since("all") is None
    db.close()


def test_summary_buckets():
    db = _Session()
    _clear(db)
    _seed(db)
    summary = audit_service.summarize_audit_events(db)
    assert summary["total_events"] == 4
    assert summary["failed_logins"] == 1
    assert summary["soar_actions"] == 1
    assert summary["agent_changes"] == 1
    assert summary["alert_status_changes"] == 0
    assert summary["ai_triage_requests"] == 0
    db.close()


def test_distinct_actors():
    db = _Session()
    _clear(db)
    _seed(db)
    assert audit_service.list_distinct_actors(db) == ["admin", "analyst01"]
    db.close()
