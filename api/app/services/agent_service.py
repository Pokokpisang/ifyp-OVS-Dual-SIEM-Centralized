"""
agent_service.py — Business logic for agent lifecycle management.

Responsibilities:
  - create_agent()           : generate token, persist agent record
  - register_agent()         : validate one-time token, activate agent, issue agent_key
  - process_heartbeat()      : update last_seen
  - compute_agent_status()   : server-side offline detection (no reliance on agent self-reporting)
  - list_agents()            : query all AgentRecord rows with live status
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import models

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOKEN_TTL_HOURS = 1  # Registration token expires after 1 hour
OFFLINE_THRESHOLD_MINUTES = 5  # Agent considered offline after 5 min without heartbeat


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(value: str) -> str:
    """Return lowercase hex SHA-256 digest of *value*."""
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def create_agent(
    *,
    agent_name: str,
    group: str,
    tags: str,
    os_type: str,
    distribution: str,
    architecture: str,
    enable_logs: bool,
    enable_fim: bool,
    enable_metrics: bool,
    db: Session,
) -> tuple[models.AgentRecord, str]:
    """
    Persist a new *pending* agent record.

    Returns
    -------
    (agent_record, raw_token)
        ``raw_token`` is the one-time registration token shown to the admin.
        It is **not** stored — only its SHA-256 hash is persisted.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = _sha256(raw_token)
    expires_at = datetime.utcnow() + timedelta(hours=TOKEN_TTL_HOURS)

    agent = models.AgentRecord(
        agent_name=agent_name,
        agent_id=str(uuid.uuid4()),
        registration_token_hash=token_hash,
        registration_token_expires_at=expires_at,
        group=group,
        tags=tags,
        os_type=os_type,
        distribution=distribution,
        architecture=architecture,
        enable_logs=enable_logs,
        enable_fim=enable_fim,
        enable_metrics=enable_metrics,
        status="pending",
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent, raw_token


def register_agent(
    *,
    token: str,
    hostname: str,
    ip_address: str,
    os: str,
    arch: str,
    db: Session,
) -> str:
    """
    Validate the one-time registration token and activate the agent.

    On success:
    - Marks agent ``active``
    - Nulls out the token hash (one-time use)
    - Generates and stores a permanent ``agent_key`` hash
    - Returns the raw ``agent_key`` for the installer to save locally

    Raises
    ------
    HTTPException 401  — invalid token, expired token, or non-pending agent
    """
    token_hash = _sha256(token)
    now = datetime.utcnow()

    agent = (
        db.query(models.AgentRecord)
        .filter(
            models.AgentRecord.registration_token_hash == token_hash,
            models.AgentRecord.status == "pending",
            models.AgentRecord.registration_token_expires_at > now,
        )
        .first()
    )

    if not agent:
        raise HTTPException(
            status_code=401,
            detail="Invalid, expired, or already-used registration token.",
        )

    # Generate permanent agent key
    raw_key = secrets.token_urlsafe(32)
    agent.agent_key_hash = _sha256(raw_key)

    # Invalidate one-time token
    agent.registration_token_hash = None
    agent.registration_token_expires_at = None

    # Activate
    agent.status = "active"
    agent.hostname = hostname
    agent.ip_address = ip_address
    agent.last_seen = now

    db.commit()
    return raw_key


def process_heartbeat(*, agent_key: str, db: Session) -> models.AgentRecord:
    """
    Update ``last_seen`` for the agent matching *agent_key*.

    Raises
    ------
    HTTPException 401  — key not found
    """
    key_hash = _sha256(agent_key)
    agent = (
        db.query(models.AgentRecord)
        .filter(models.AgentRecord.agent_key_hash == key_hash)
        .first()
    )
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent key.")

    agent.last_seen = datetime.utcnow()
    agent.status = "active"
    db.commit()
    db.refresh(agent)
    return agent


def regenerate_agent_token(agent_id: str, db: Session) -> str:
    """
    Generate a new one-time registration token for an existing agent.
    This allows the 'REINSTALL' flow to work.
    """
    import secrets
    import hashlib
    from .agent_service import TOKEN_TTL_HOURS
    
    agent = db.query(models.AgentRecord).filter(models.AgentRecord.agent_id == agent_id).first()
    if not agent:
        return None
        
    raw_token = secrets.token_hex(16)
    agent.registration_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    agent.token_expires_at = datetime.utcnow() + timedelta(hours=TOKEN_TTL_HOURS)
    
    db.commit()
    return raw_token


def update_last_seen(*, agent_key: str, db: Session) -> bool:
    """
    Quietly update last_seen if agent_key is valid. 
    Returns True if updated, False otherwise.
    Used by logs and metrics endpoints to avoid explicit heartbeat overhead.
    """
    if not agent_key:
        return False
    try:
        process_heartbeat(agent_key=agent_key, db=db)
        return True
    except HTTPException:
        return False


def compute_agent_status(agent: models.AgentRecord) -> str:
    """
    Derive the *current* status of *agent* at read time.

    Server-side offline detection: we do not rely on the agent to self-report
    its own death.  If ``last_seen`` is older than OFFLINE_THRESHOLD_MINUTES we
    flip the status to ``offline``.
    """
    if agent.status == "pending":
        return "pending"
    if agent.last_seen is None:
        return "offline"
    if datetime.utcnow() - agent.last_seen > timedelta(minutes=OFFLINE_THRESHOLD_MINUTES):
        return "offline"
    return "active"


def list_agents(db: Session) -> list[dict]:
    """
    Return all agent records with live-computed status.
    """
    agents = db.query(models.AgentRecord).order_by(models.AgentRecord.created_at.desc()).all()
    result = []
    for a in agents:
        result.append(
            {
                "id": a.id,
                "agent_id": a.agent_id,
                "agent_name": a.agent_name,
                "group": a.group,
                "tags": a.tags,
                "os_type": a.os_type,
                "distribution": a.distribution,
                "architecture": a.architecture,
                "status": compute_agent_status(a),
                "hostname": a.hostname or "—",
                "ip_address": a.ip_address or "—",
                "last_seen": a.last_seen.strftime("%Y-%m-%d %H:%M UTC") if a.last_seen else "Never",
                "created_at": a.created_at.strftime("%Y-%m-%d %H:%M UTC") if a.created_at else "—",
                "enable_logs": a.enable_logs,
                "enable_fim": a.enable_fim,
                "enable_metrics": a.enable_metrics,
            }
        )
    return result
def get_agent_by_id(agent_id: str, db: Session) -> models.AgentRecord | None:
    """Return the AgentRecord with the given agent_id (UUID string)."""
    return db.query(models.AgentRecord).filter(models.AgentRecord.agent_id == agent_id).first()


def delete_agent_by_id(agent_id: str, db: Session) -> bool:
    """Delete the AgentRecord with the given agent_id. Returns True if deleted."""
    agent = get_agent_by_id(agent_id, db)
    if agent:
        db.delete(agent)
        db.commit()
        return True
    return False


def get_latest_agent_metrics(host: str, db: Session) -> models.Metric | None:
    """Return the most recent Metric record for the given host."""
    if not host:
        return None
    return (
        db.query(models.Metric)
        .filter(models.Metric.host == host)
        .order_by(models.Metric.timestamp.desc())
        .first()
    )


def get_recent_agent_alerts(host: str, db: Session, limit: int = 5) -> list[models.Alert]:
    """Return the N most recent Alert records for the given host."""
    if not host:
        return []
    return (
        db.query(models.Alert)
        .filter(models.Alert.host == host)
        .order_by(models.Alert.timestamp.desc())
        .limit(limit)
        .all()
    )


def get_recent_agent_logs(host: str, db: Session, limit: int = 20) -> list[models.Log]:
    """Return the N most recent Log records for the given host."""
    if not host:
        return []
    return (
        db.query(models.Log)
        .filter(models.Log.host == host)
        .order_by(models.Log.timestamp.desc())
        .limit(limit)
        .all()
    )
