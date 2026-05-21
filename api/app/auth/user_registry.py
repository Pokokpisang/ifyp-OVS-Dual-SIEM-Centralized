"""
user_registry.py — Env-var based user registry with role support.

Env vars:
  DASHBOARD_USERNAME      — primary username
  DASHBOARD_PASSWORD_HASH — bcrypt hash (base64-encoded) for primary user
  DASHBOARD_ROLE          — role for primary user (default: "admin")

  CLIENT_USERNAME         — optional second user (blank = disabled)
  CLIENT_PASSWORD_HASH    — bcrypt hash (base64-encoded) for client user
  CLIENT_ROLE             — role for client user (default: "client")

Roles:
  "admin"  — full access including destructive/settings/SOAR operations
  "client" — read-only: can view dashboard, alerts, logs; cannot change settings
"""
import base64
import logging
import os
from typing import Optional

import bcrypt as _bcrypt

logger = logging.getLogger("ovs.auth")

_DUMMY_HASH: bytes = _bcrypt.hashpw(b"__dummy__", _bcrypt.gensalt())


def _decode_hash(b64: str) -> bytes:
    try:
        padded = b64 + "==" * ((-len(b64)) % 4)
        return base64.b64decode(padded).decode("utf-8").encode("utf-8")
    except Exception:
        return b""


def authenticate(username: str, password: str) -> Optional[str]:
    """
    Validate credentials against env-var registry.
    Returns the user's role string on success, None on failure.
    Always runs bcrypt on all candidates to prevent timing side-channels.
    """
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
