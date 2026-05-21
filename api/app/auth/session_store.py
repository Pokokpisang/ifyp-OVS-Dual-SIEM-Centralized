"""
session_store.py — PostgreSQL-backed server-side session management.

Stores sha256(raw_token) in the DB. The raw token lives only in the signed cookie.
Compromise of the DB alone does not allow session replay.
"""
import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from .. import models


def _hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _max_age_seconds() -> int:
    try:
        return int(os.getenv("SESSION_MAX_AGE_SECONDS", "28800"))  # 8h default
    except ValueError:
        return 28800


def create_session(username: str, role: str, db: Session) -> str:
    """Insert a new server session and return the raw token (goes into cookie)."""
    purge_expired_sessions(db)
    raw_token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    db.add(models.ServerSession(
        token_hash=_hash(raw_token),
        username=username,
        role=role,
        created_at=now,
        expires_at=now + timedelta(seconds=_max_age_seconds()),
    ))
    db.commit()
    return raw_token


def validate_session(raw_token: str, db: Session) -> Optional[dict]:
    """Return {"username": ..., "role": ...} if token is valid and not expired."""
    if not raw_token:
        return None
    row = (
        db.query(models.ServerSession)
        .filter(
            models.ServerSession.token_hash == _hash(raw_token),
            models.ServerSession.expires_at > datetime.utcnow(),
        )
        .first()
    )
    return {"username": row.username, "role": row.role} if row else None


def delete_session(raw_token: str, db: Session) -> None:
    """Delete a single session row (called on logout — ST-010 revocation)."""
    if not raw_token:
        return
    db.query(models.ServerSession).filter(
        models.ServerSession.token_hash == _hash(raw_token)
    ).delete()
    db.commit()


def purge_expired_sessions(db: Session) -> int:
    """Delete all expired session rows. Called on every login and at startup."""
    deleted = (
        db.query(models.ServerSession)
        .filter(models.ServerSession.expires_at < datetime.utcnow())
        .delete()
    )
    db.commit()
    return deleted
