"""
test_portal_api.py — read-only client-portal API (v2.13.0, Phase 4B).

Covers the portal's hard rules:
- GET-only surface (no mutation route may exist under /api/portal/)
- portal-safe serializers (no rule internals, keys, or internal UUIDs)
- key auth: missing/invalid/suspended/revoked all fail closed with 401
- tenant isolation through the endpoints themselves
"""
import asyncio
import uuid
from datetime import datetime

import httpx
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db as db_module
from app.models import Base, AgentRecord, Alert, Client
from app.routers import portal
from app.routers.auth import limiter
from app.services import client_service as cs

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)

_app = FastAPI()
_app.include_router(portal.router)


def _override_db():
    session = _Session()
    try:
        yield session
    finally:
        session.close()


_app.dependency_overrides[db_module.get_db] = _override_db
limiter.enabled = False  # rate limits are config, not logic under test


def _db():
    db = _Session()
    for model in (Alert, AgentRecord, Client):
        db.query(model).delete()
    db.commit()
    return db


def _seed_tenant(db, name, host_prefix):
    client = cs.create_client(db, name=name)
    db.commit()
    _, raw_key = cs.issue_api_key(db, client.id)
    db.commit()
    agent = AgentRecord(
        agent_name=f"{host_prefix}-web-01", agent_id=str(uuid.uuid4()),
        hostname=f"{host_prefix}-web-01.lab", status="active",
        client_id=client.id, last_seen=datetime.utcnow(),
    )
    db.add(agent)
    db.commit()
    db.add(Alert(severity="HIGH", title=f"{name} alert", host=agent.hostname,
                 agent_id=agent.agent_id, is_read=False, timestamp=datetime.utcnow(),
                 detection_metadata='{"secret_rule_internals": true}',
                 dedup_key="internal-dedup", rule_id="internal-rule"))
    db.commit()
    return client, raw_key


def _get(path, key=None):
    async def _run():
        headers = {"X-Client-Key": key} if key else {}
        transport = httpx.ASGITransport(app=_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://portal") as c:
            return await c.get(path, headers=headers)
    return asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# Structural contracts
# ---------------------------------------------------------------------------

def test_portal_surface_is_get_only():
    for route in portal.router.routes:
        methods = route.methods - {"HEAD", "OPTIONS"}
        assert methods == {"GET"}, f"{route.path} allows {methods}"


def test_serializers_expose_only_portal_safe_fields():
    agent = AgentRecord(agent_name="a", agent_id="uuid-internal", hostname="h",
                        agent_key_hash="KEYHASH", registration_token_hash="TOKHASH")
    data = portal._agent_public(agent)
    assert set(data) == {"name", "hostname", "ip_address", "os", "status", "last_seen", "monitored_since"}
    assert "uuid-internal" not in str(data) and "KEYHASH" not in str(data)

    alert = Alert(id=1, severity="HIGH", title="t", host="h",
                  detection_metadata='{"x":1}', dedup_key="dk", rule_id="r", agent_id="uuid")
    data = portal._alert_public(alert)
    assert set(data) == {"id", "timestamp", "severity", "title", "description",
                         "host", "mitre_tactic", "mitre_technique", "risk_score"}


# ---------------------------------------------------------------------------
# Auth: fail closed
# ---------------------------------------------------------------------------

def test_auth_fails_closed():
    db = _db()
    client, key = _seed_tenant(db, "Tenant Auth", "auth")

    assert _get("/api/portal/summary").status_code == 401                 # no key
    assert _get("/api/portal/summary", "ovsc_wrong").status_code == 401   # bad key
    assert _get("/api/portal/summary", key).status_code == 200            # good key

    client.status = "suspended"
    db.commit()
    assert _get("/api/portal/summary", key).status_code == 401            # suspended

    client.status = "active"
    db.commit()
    cs.revoke_api_key(db, client.id)
    db.commit()
    assert _get("/api/portal/summary", key).status_code == 401            # revoked
    db.close()


# ---------------------------------------------------------------------------
# Tenant isolation through the endpoints
# ---------------------------------------------------------------------------

def test_endpoints_are_tenant_isolated():
    db = _db()
    _, key_a = _seed_tenant(db, "Tenant A", "aa")
    _, key_b = _seed_tenant(db, "Tenant B", "bb")

    for key, own, other in ((key_a, "Tenant A", "Tenant B"), (key_b, "Tenant B", "Tenant A")):
        alerts = _get("/api/portal/alerts", key).json()["alerts"]
        titles = {a["title"] for a in alerts}
        assert titles == {f"{own} alert"}, titles
        # No rule internals leak through the alerts payload
        blob = str(alerts)
        assert "secret_rule_internals" not in blob and "internal-dedup" not in blob and "internal-rule" not in blob

        agents = _get("/api/portal/agents", key).json()["agents"]
        assert len(agents) == 1 and other.lower()[:2] not in agents[0]["hostname"]

        summary = _get("/api/portal/summary", key).json()
        assert summary["client"]["name"] == own
        assert summary["agents"]["total"] == 1 and summary["alerts"]["total"] == 1
    db.close()


def test_summary_and_posture_shapes():
    db = _db()
    _, key = _seed_tenant(db, "Tenant S", "ss")
    summary = _get("/api/portal/summary", key).json()
    assert summary["alerts"]["by_severity"] == {"HIGH": 1}
    assert summary["alerts"]["last_24h"] == 1

    posture = _get("/api/portal/security-summary?days=7", key).json()
    assert posture["total_alerts"] == 1
    assert posture["by_severity"] == {"HIGH": 1}
    assert posture["top_hosts"][0]["host"] == "ss-web-01.lab"

    r = _get("/api/portal/alerts?severity=LOW", key)
    assert r.json()["total"] == 0  # severity filter works
    db.close()
