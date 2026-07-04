"""
user_service — DB-backed dashboard user management (admin-only callers).

Safety rails:
- usernames colliding with the env bootstrap accounts are rejected;
- an admin cannot change their own role, deactivate, or delete themselves;
- the last active DB admin cannot be demoted/deactivated/deleted unless an
  env bootstrap admin is configured as break-glass;
- deactivation, deletion, and role changes revoke the user's live sessions
  immediately (role is baked into the session row at login).

Passwords are bcrypt-hashed here; plaintext is never stored, logged, or
audited (the audit scrubber would redact a "password" key anyway).
"""
import logging
import os
from typing import List, Optional

import bcrypt
from sqlalchemy.orm import Session

from .. import models
from ..auth.user_registry import ROLES, env_usernames

logger = logging.getLogger("services.users")

MIN_PASSWORD_LENGTH = 12


class UserServiceError(ValueError):
    """Validation/guard failure — message is safe to surface to the admin UI."""


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _env_admin_configured() -> bool:
    return bool(os.getenv("DASHBOARD_USERNAME")) and os.getenv("DASHBOARD_ROLE", "admin") == "admin"


def _revoke_sessions(db: Session, username: str) -> int:
    count = (
        db.query(models.ServerSession)
        .filter(models.ServerSession.username == username)
        .delete()
    )
    if count:
        logger.info("[USERS] Revoked %d session(s) for %s", count, username)
    return count


def _other_active_admin_exists(db: Session, excluding_id: int) -> bool:
    return (
        db.query(models.User.id)
        .filter(
            models.User.id != excluding_id,
            models.User.role == "admin",
            models.User.is_active == True,  # noqa: E712
        )
        .first()
        is not None
    )


def _guard_not_last_admin(db: Session, user: models.User) -> None:
    if user.role != "admin" or not user.is_active:
        return
    if not _other_active_admin_exists(db, user.id) and not _env_admin_configured():
        raise UserServiceError(
            "Cannot remove the last active admin — no environment bootstrap admin is configured."
        )


def validate_password(password: str) -> None:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise UserServiceError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")


def list_users(db: Session) -> List[models.User]:
    return db.query(models.User).order_by(models.User.id).all()


def create_user(db: Session, *, username: str, password: str, role: str) -> models.User:
    username = (username or "").strip()
    if not username:
        raise UserServiceError("Username is required.")
    if role not in ROLES:
        raise UserServiceError(f"Role must be one of {ROLES}.")
    validate_password(password)
    if username in env_usernames():
        raise UserServiceError("This username is reserved by an environment bootstrap account.")
    if db.query(models.User.id).filter(models.User.username == username).first():
        raise UserServiceError("Username already exists.")

    user = models.User(username=username, password_hash=_hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user


def update_user(
    db: Session,
    user_id: int,
    *,
    acting_username: str,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    new_password: Optional[str] = None,
) -> tuple:
    """Apply changes; returns (user, changes dict for auditing)."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise UserServiceError("User not found.")

    is_self = user.username == acting_username
    changes = {}

    if role is not None and role != user.role:
        if role not in ROLES:
            raise UserServiceError(f"Role must be one of {ROLES}.")
        if is_self:
            raise UserServiceError("You cannot change your own role.")
        _guard_not_last_admin(db, user)
        changes["role"] = f"{user.role} → {role}"
        user.role = role
        _revoke_sessions(db, user.username)  # session role is stale — force re-login

    if is_active is not None and is_active != user.is_active:
        if is_self:
            raise UserServiceError("You cannot deactivate your own account.")
        if not is_active:
            _guard_not_last_admin(db, user)
            _revoke_sessions(db, user.username)
        changes["is_active"] = f"{user.is_active} → {is_active}"
        user.is_active = is_active

    if new_password:
        validate_password(new_password)
        user.password_hash = _hash_password(new_password)
        changes["password"] = "reset"  # audit scrubber redacts the value slot anyway
        if not is_self:
            _revoke_sessions(db, user.username)

    return user, changes


def delete_user(db: Session, user_id: int, *, acting_username: str) -> models.User:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise UserServiceError("User not found.")
    if user.username == acting_username:
        raise UserServiceError("You cannot delete your own account.")
    _guard_not_last_admin(db, user)
    _revoke_sessions(db, user.username)
    db.delete(user)
    return user
