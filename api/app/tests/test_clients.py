"""
test_clients.py — tenant (client) layer foundation (v2.13.0).

Covers: client CRUD guards, agent assignment/unassignment, API-key
lifecycle (hash-only storage, active-status gate), and — most importantly —
tenant scoping: client_alerts_query must never leak another tenant's or
unassigned agents' data, and an empty client matches nothing (fail closed).
"""
import uuid
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, AgentRecord, Alert, Client
from app.services import client_service as cs

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _db():
    db = _Session()
    for model in (Alert, AgentRecord, Client):
        db.query(model).delete()
    db.commit()
    return db


def _agent(db, name, client_id=None, hostname=None):
    agent = AgentRecord(
        agent_name=name, agent_id=str(uuid.uuid4()),
        hostname=hostname or f"{name}.lab", status="active",
        client_id=client_id, last_seen=datetime.utcnow(),
    )
    db.add(agent)
    db.commit()
    return agent


def _alert(db, host, agent_id=None, title="alert"):
    alert = Alert(severity="HIGH", title=title, host=host, agent_id=agent_id, is_read=False)
    db.add(alert)
    db.commit()
    return alert


# ---------------------------------------------------------------------------
# CRUD guards
# ---------------------------------------------------------------------------

def test_create_client_validation():
    db = _db()
    cs.create_client(db, name="Northwind Cloud")
    db.commit()
    with pytest.raises(cs.ClientServiceError):
        cs.create_client(db, name="Northwind Cloud")  # duplicate
    with pytest.raises(cs.ClientServiceError):
        cs.create_client(db, name="")
    with pytest.raises(cs.ClientServiceError):
        cs.create_client(db, name="X", org_type="Cartel")
    with pytest.raises(cs.ClientServiceError):
        cs.create_client(db, name="X", status="vip")
    db.close()


def test_delete_client_unassigns_agents_keeps_data():
    db = _db()
    client = cs.create_client(db, name="Bluepine")
    db.commit()
    agent = _agent(db, "edge-01", client_id=client.id)
    _alert(db, agent.hostname, agent_id=agent.agent_id)

    cs.delete_client(db, client.id)
    db.commit()
    db.refresh(agent)
    assert agent.client_id is None          # unassigned, not deleted
    assert db.query(Alert).count() == 1     # data retained
    db.close()


# ---------------------------------------------------------------------------
# API key lifecycle
# ---------------------------------------------------------------------------

def test_api_key_issue_rotate_revoke_and_status_gate():
    db = _db()
    client = cs.create_client(db, name="Halcyon")
    db.commit()

    assert cs.get_client_by_api_key(db, "anything") is None

    _, raw1 = cs.issue_api_key(db, client.id)
    db.commit()
    assert raw1.startswith("ovsc_")
    assert client.api_key_hash != raw1          # hashed, never raw
    assert raw1 not in (client.api_key_hash or "")
    assert cs.get_client_by_api_key(db, raw1).id == client.id

    # Rotation invalidates the old key
    _, raw2 = cs.issue_api_key(db, client.id)
    db.commit()
    assert cs.get_client_by_api_key(db, raw1) is None
    assert cs.get_client_by_api_key(db, raw2).id == client.id

    # Non-active status fails closed without touching the key
    client.status = "suspended"
    db.commit()
    assert cs.get_client_by_api_key(db, raw2) is None
    client.status = "active"
    db.commit()
    assert cs.get_client_by_api_key(db, raw2).id == client.id

    # Revocation
    cs.revoke_api_key(db, client.id)
    db.commit()
    assert cs.get_client_by_api_key(db, raw2) is None
    db.close()


# ---------------------------------------------------------------------------
# Tenant scoping — the isolation contract
# ---------------------------------------------------------------------------

def test_alert_scoping_never_leaks_across_tenants():
    db = _db()
    c1 = cs.create_client(db, name="Tenant A")
    c2 = cs.create_client(db, name="Tenant B")
    db.commit()

    a1 = _agent(db, "a-web-01", client_id=c1.id)
    a2 = _agent(db, "b-web-01", client_id=c2.id)
    soc_only = _agent(db, "soc-internal-01", client_id=None)

    _alert(db, a1.hostname, agent_id=a1.agent_id, title="tenant A alert")
    _alert(db, a2.hostname, agent_id=a2.agent_id, title="tenant B alert")
    _alert(db, soc_only.hostname, agent_id=soc_only.agent_id, title="soc internal alert")
    _alert(db, a1.agent_name, title="tenant A by-hostname alert")  # host match, no agent_id

    titles_c1 = {a.title for a in cs.client_alerts_query(db, c1.id).all()}
    titles_c2 = {a.title for a in cs.client_alerts_query(db, c2.id).all()}

    assert titles_c1 == {"tenant A alert", "tenant A by-hostname alert"}
    assert titles_c2 == {"tenant B alert"}
    assert "soc internal alert" not in titles_c1 | titles_c2
    db.close()


def test_empty_client_matches_nothing_fail_closed():
    db = _db()
    empty = cs.create_client(db, name="Empty Co")
    db.commit()
    _alert(db, "some-host", title="global alert")
    assert cs.client_alerts_query(db, empty.id).count() == 0
    db.close()


def test_unassign_removes_scope():
    db = _db()
    client = cs.create_client(db, name="Meridian")
    db.commit()
    agent = _agent(db, "worker-02", client_id=client.id)
    _alert(db, agent.hostname, agent_id=agent.agent_id)
    assert cs.client_alerts_query(db, client.id).count() == 1

    cs.unassign_agent(db, agent.agent_id)
    db.commit()
    assert cs.client_alerts_query(db, client.id).count() == 0  # scope gone immediately
    db.close()


def test_rollup_counts():
    db = _db()
    client = cs.create_client(db, name="Quantra")
    db.commit()
    a1 = _agent(db, "q-1", client_id=client.id)
    _agent(db, "q-2", client_id=client.id).last_seen = datetime(2020, 1, 1)  # long silent
    db.commit()
    _alert(db, a1.hostname, agent_id=a1.agent_id)

    roll = cs.client_rollup(db, client)
    assert roll["agents_total"] == 2
    assert roll["agents_online"] == 1
    assert roll["agents_offline"] == 1
    assert roll["open_alerts"] == 1
    assert roll["api_key_set"] is False
    db.close()
