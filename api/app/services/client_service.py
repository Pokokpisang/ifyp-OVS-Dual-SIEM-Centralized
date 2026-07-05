"""
client_service — tenant (client) management for the SOC side.

Tenancy model: agents carry a nullable ``client_id``; everything else
(alerts, logs, metrics) is scoped *through* the agent assignment — an
alert/log/metric belongs to a client iff its host matches one of that
client's agents. Unassigned agents are SOC-internal and invisible to any
portal credential.

The portal API key is issued/rotated here by SOC admins: the raw key is
returned exactly once and only its SHA-256 lands in the DB (same pattern as
agent keys). Suspending a client makes its key unusable without deleting it.
"""
import hashlib
import logging
import secrets
from datetime import datetime
from typing import List, Optional, Set, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from .agent_service import compute_agent_status

logger = logging.getLogger("services.clients")

ORG_TYPES = ("Hosting Provider", "MSP", "SaaS", "Other")
STATUSES = ("active", "trial", "suspended")


class ClientServiceError(ValueError):
    """Validation/guard failure — message safe for the admin UI."""


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def list_clients(db: Session) -> List[models.Client]:
    return db.query(models.Client).order_by(models.Client.name).all()


def get_client(db: Session, client_id: int) -> models.Client:
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if client is None:
        raise ClientServiceError("Client not found.")
    return client


def get_client_by_api_key(db: Session, raw_key: str) -> Optional[models.Client]:
    """Portal auth: resolve an ACTIVE client from its raw API key.

    Suspended/trial-expired handling: only ``status == "active"`` clients may
    read portal data; anything else fails closed.
    """
    if not raw_key:
        return None
    return (
        db.query(models.Client)
        .filter(
            models.Client.api_key_hash == _sha256(raw_key),
            models.Client.status == "active",
        )
        .first()
    )


def create_client(db: Session, *, name: str, org_type: str = "Hosting Provider",
                  contact_name: str = "", contact_email: str = "",
                  status: str = "active") -> models.Client:
    name = (name or "").strip()
    if not name:
        raise ClientServiceError("Client name is required.")
    if org_type not in ORG_TYPES:
        raise ClientServiceError(f"org_type must be one of {ORG_TYPES}.")
    if status not in STATUSES:
        raise ClientServiceError(f"status must be one of {STATUSES}.")
    if db.query(models.Client.id).filter(models.Client.name == name).first():
        raise ClientServiceError("A client with this name already exists.")
    client = models.Client(
        name=name, org_type=org_type,
        contact_name=contact_name.strip(), contact_email=contact_email.strip(),
        status=status,
    )
    db.add(client)
    db.flush()
    return client


def update_client(db: Session, client_id: int, **fields) -> Tuple[models.Client, dict]:
    client = get_client(db, client_id)
    changes = {}
    for key in ("name", "org_type", "contact_name", "contact_email", "status"):
        value = fields.get(key)
        if value is None:
            continue
        value = value.strip() if isinstance(value, str) else value
        if key == "name":
            if not value:
                raise ClientServiceError("Client name is required.")
            clash = db.query(models.Client.id).filter(
                models.Client.name == value, models.Client.id != client_id).first()
            if clash:
                raise ClientServiceError("A client with this name already exists.")
        if key == "org_type" and value not in ORG_TYPES:
            raise ClientServiceError(f"org_type must be one of {ORG_TYPES}.")
        if key == "status" and value not in STATUSES:
            raise ClientServiceError(f"status must be one of {STATUSES}.")
        current = getattr(client, key)
        if value != current:
            changes[key] = f"{current} → {value}"
            setattr(client, key, value)
    return client, changes


def delete_client(db: Session, client_id: int) -> models.Client:
    """Delete a client; its agents become unassigned (SOC-internal)."""
    client = get_client(db, client_id)
    (
        db.query(models.AgentRecord)
        .filter(models.AgentRecord.client_id == client_id)
        .update({models.AgentRecord.client_id: None})
    )
    db.delete(client)
    return client


def issue_api_key(db: Session, client_id: int) -> Tuple[models.Client, str]:
    """Generate (or rotate) the portal API key. Returns (client, RAW key).
    The raw key is shown once and never stored or logged."""
    client = get_client(db, client_id)
    raw_key = "ovsc_" + secrets.token_urlsafe(32)
    client.api_key_hash = _sha256(raw_key)
    client.api_key_rotated_at = datetime.utcnow()
    return client, raw_key


def revoke_api_key(db: Session, client_id: int) -> models.Client:
    client = get_client(db, client_id)
    client.api_key_hash = None
    client.api_key_rotated_at = datetime.utcnow()
    return client


# ---------------------------------------------------------------------------
# Agent assignment + tenant scoping
# ---------------------------------------------------------------------------

def assign_agents(db: Session, client_id: int, agent_ids: List[str]) -> List[str]:
    """Assign agents (by agent_id UUID) to the client. Returns assigned ids."""
    get_client(db, client_id)  # 404 guard
    assigned = []
    for agent_id in agent_ids:
        agent = (
            db.query(models.AgentRecord)
            .filter(models.AgentRecord.agent_id == agent_id,
                    models.AgentRecord.is_deleted == False)  # noqa: E712
            .first()
        )
        if agent is not None:
            agent.client_id = client_id
            assigned.append(agent_id)
    return assigned


def unassign_agent(db: Session, agent_id: str) -> bool:
    agent = (
        db.query(models.AgentRecord)
        .filter(models.AgentRecord.agent_id == agent_id)
        .first()
    )
    if agent is None:
        return False
    agent.client_id = None
    return True


def client_agents(db: Session, client_id: int) -> List[models.AgentRecord]:
    return (
        db.query(models.AgentRecord)
        .filter(models.AgentRecord.client_id == client_id,
                models.AgentRecord.is_deleted == False)  # noqa: E712
        .order_by(models.AgentRecord.agent_name)
        .all()
    )


def client_hostnames(db: Session, client_id: int) -> Set[str]:
    """The host identifiers that scope alerts/logs/metrics to this client.
    THE single choke point for tenant filtering — every portal query and
    rollup must derive its host set from here."""
    hosts: Set[str] = set()
    for agent in client_agents(db, client_id):
        if agent.hostname:
            hosts.add(agent.hostname)
        if agent.agent_name:
            hosts.add(agent.agent_name)
    return hosts


def client_alerts_query(db: Session, client_id: int):
    """Tenant-scoped alerts query (agent_id OR host match)."""
    agents = client_agents(db, client_id)
    agent_ids = [a.agent_id for a in agents]
    hosts = client_hostnames(db, client_id)
    if not agent_ids and not hosts:
        # No agents assigned — match nothing (never fall open to all alerts).
        return db.query(models.Alert).filter(models.Alert.id == None)  # noqa: E711
    return db.query(models.Alert).filter(
        (models.Alert.agent_id.in_(agent_ids)) | (models.Alert.host.in_(hosts))
    )


def client_rollup(db: Session, client: models.Client) -> dict:
    """Summary numbers for the clients list/detail pages."""
    agents = client_agents(db, client.id)
    statuses = [compute_agent_status(a) for a in agents]
    open_alerts = (
        client_alerts_query(db, client.id)
        .filter(models.Alert.is_read == False)  # noqa: E712
        .with_entities(func.count(models.Alert.id))
        .scalar() or 0
    )
    return {
        "id": client.id,
        "name": client.name,
        "org_type": client.org_type,
        "contact_name": client.contact_name,
        "contact_email": client.contact_email,
        "status": client.status,
        "agents_total": len(agents),
        "agents_online": sum(1 for s in statuses if s == "active"),
        "agents_offline": sum(1 for s in statuses if s == "offline"),
        "agents_pending": sum(1 for s in statuses if s == "pending"),
        "open_alerts": open_alerts,
        "api_key_set": client.api_key_hash is not None,
        "api_key_rotated_at": client.api_key_rotated_at.strftime("%Y-%m-%d %H:%M") if client.api_key_rotated_at else None,
        "created_at": client.created_at.strftime("%Y-%m-%d") if client.created_at else None,
    }
