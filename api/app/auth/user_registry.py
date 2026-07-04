"""
user_registry.py — user authentication: DB-backed users + env-var bootstrap.

DB users (``models.User``, managed at /settings/users) are checked first; a
DB row with a matching username is authoritative — env fallback is skipped
for that username so a deactivated DB user cannot log in via a stale env
entry. The env accounts remain as break-glass bootstrap logins.

Env vars:
  DASHBOARD_USERNAME      — primary username
  DASHBOARD_PASSWORD_HASH — bcrypt hash (base64-encoded) for primary user
  DASHBOARD_ROLE          — role for primary user (default: "admin")

  CLIENT_USERNAME         — optional second user (blank = disabled)
  CLIENT_PASSWORD_HASH    — bcrypt hash (base64-encoded) for client user
  CLIENT_ROLE             — role for client user (default: "client")

Roles:
  "admin"   — full access including destructive/settings/SOAR operations
  "analyst" — SOC operations (SOAR run, investigation); no settings/user admin
  "client"  — read-only: can view dashboard, alerts, logs
"""
import base64
import logging
import os
from datetime import datetime
from typing import Optional

import bcrypt as _bcrypt
from sqlalchemy.orm import Session

from .. import models

logger = logging.getLogger("ovs.auth")

ROLES = ("admin", "analyst", "client")

_DUMMY_HASH: bytes = _bcrypt.hashpw(b"__dummy__", _bcrypt.gensalt())


def _decode_hash(b64: str) -> bytes:
    try:
        padded = b64 + "==" * ((-len(b64)) % 4)
        return base64.b64decode(padded).decode("utf-8").encode("utf-8")
    except Exception:
        return b""


def env_usernames() -> list:
    """Usernames reserved by the env bootstrap accounts."""
    return [u for u in (os.getenv("DASHBOARD_USERNAME", ""), os.getenv("CLIENT_USERNAME", "")) if u]


def _authenticate_db(username: str, password: str, db: Session) -> Optional[str]:
    """Check DB users. Returns role, or None. A username match (active or
    not) is authoritative — callers must not fall back to env for it."""
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        return None
    try:
        ok = _bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8"))
    except Exception:
        ok = False
    if ok and user.is_active:
        user.last_login = datetime.utcnow()  # committed with the session row
        return user.role
    return None


def authenticate(username: str, password: str, db: Optional[Session] = None) -> Optional[str]:
    """
    Validate credentials against DB users, then the env-var registry.
    Returns the user's role string on success, None on failure.
    Always runs bcrypt on all candidates to prevent timing side-channels.
    """
    if db is not None:
        exists = db.query(models.User.id).filter(models.User.username == username).first() is not None
        if exists:
            return _authenticate_db(username, password, db)

    candidates = []

    primary_user = os.getenv("DASHBOARD_USERNAME", "")
    primary_hash = _decode_hash(os.getenv("DASHBOARD_PASSWORD_HASH", ""))
    primary_role = os.getenv("DASHBOARD_ROLE", "admin")
    if primary_user:
        candidates.append((primary_user, primary_hash, primary_role))

    client_user = os.getenv("CLIENT_USERNAME", "")
    client_hash = _decode_hash(os.getenv("CLIENT_PASSWORD_HASH", ""))
    client_role = os.getenv("CLIENT_ROLE", "client")
    if client_user:
        candidates.append((client_user, client_hash, client_role))

    if not candidates:
        _bcrypt.checkpw(b"dummy", _DUMMY_HASH)
        return None

    if not client_user:
        logger.debug("AUTH_REGISTRY client user not configured; admin-only login")

    matched_role: Optional[str] = None
    for cand_user, cand_hash, cand_role in candidates:
        check_hash = cand_hash if cand_hash else _DUMMY_HASH
        try:
            ok = _bcrypt.checkpw(password.encode("utf-8"), check_hash)
        except Exception:
            ok = False
        if ok and username == cand_user and cand_hash:
            matched_role = cand_role

    return matched_role
