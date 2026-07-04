"""
test_users.py — DB-backed users + RBAC management (v2.12.0).

Covers: DB-first authentication with env fallback, inactive-user rejection,
DB-shadowing rules, CRUD guards (self-protection, last-admin, reserved
usernames, password policy), and session revocation on role change /
deactivation / deletion.
"""
import base64

import bcrypt
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, ServerSession, User
from app.auth.user_registry import authenticate
from app.services.user_service import (
    UserServiceError,
    create_user,
    delete_user,
    update_user,
)

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)

PW = "correct-horse-battery"


def _db():
    db = _Session()
    db.query(ServerSession).delete()
    db.query(User).delete()
    db.commit()
    return db


def _mk(db, username="alice", role="analyst", password=PW, is_active=True):
    user = create_user(db, username=username, password=password, role=role)
    user.is_active = is_active
    db.commit()
    return user


def _env_admin(monkeypatch, username="envadmin", password="env-password-123"):
    raw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    monkeypatch.setenv("DASHBOARD_USERNAME", username)
    monkeypatch.setenv("DASHBOARD_PASSWORD_HASH", base64.b64encode(raw).decode())
    monkeypatch.setenv("DASHBOARD_ROLE", "admin")
    monkeypatch.delenv("CLIENT_USERNAME", raising=False)


# ---------------------------------------------------------------------------
# authenticate()
# ---------------------------------------------------------------------------

def test_db_user_authenticates_and_records_last_login(monkeypatch):
    _env_admin(monkeypatch)
    db = _db()
    _mk(db, role="analyst")
    assert authenticate("alice", PW, db=db) == "analyst"
    db.commit()
    assert db.query(User).filter_by(username="alice").first().last_login is not None
    assert authenticate("alice", "wrong-password-xx", db=db) is None
    db.close()


def test_inactive_db_user_rejected_without_env_fallback(monkeypatch):
    # A DB row is authoritative for its username: deactivation must not fall
    # back to an env account with the same name.
    _env_admin(monkeypatch, username="alice", password=PW)
    db = _db()
    user = db.query(User)  # noqa: F841
    u = User(username="alice", password_hash=bcrypt.hashpw(PW.encode(), bcrypt.gensalt()).decode(),
             role="admin", is_active=False)
    db.add(u)
    db.commit()
    assert authenticate("alice", PW, db=db) is None
    db.close()


def test_env_fallback_still_works_for_non_db_usernames(monkeypatch):
    _env_admin(monkeypatch, username="envadmin", password="env-password-123")
    db = _db()
    _mk(db)  # unrelated DB user
    assert authenticate("envadmin", "env-password-123", db=db) == "admin"
    assert authenticate("envadmin", "nope", db=db) is None
    db.close()


def test_analyst_role_now_mintable(monkeypatch):
    _env_admin(monkeypatch)
    db = _db()
    _mk(db, username="bob", role="analyst")
    assert authenticate("bob", PW, db=db) == "analyst"
    db.close()


# ---------------------------------------------------------------------------
# CRUD guards
# ---------------------------------------------------------------------------

def test_create_user_validation(monkeypatch):
    _env_admin(monkeypatch, username="envadmin")
    db = _db()
    with pytest.raises(UserServiceError):
        create_user(db, username="x", password="short", role="analyst")
    with pytest.raises(UserServiceError):
        create_user(db, username="x", password=PW, role="superuser")
    with pytest.raises(UserServiceError):
        create_user(db, username="envadmin", password=PW, role="admin")  # reserved
    _mk(db, username="dup")
    with pytest.raises(UserServiceError):
        create_user(db, username="dup", password=PW, role="analyst")
    db.close()


def test_self_protection_guards(monkeypatch):
    _env_admin(monkeypatch)
    db = _db()
    admin = _mk(db, username="root", role="admin")
    with pytest.raises(UserServiceError):
        update_user(db, admin.id, acting_username="root", role="client")
    with pytest.raises(UserServiceError):
        update_user(db, admin.id, acting_username="root", is_active=False)
    with pytest.raises(UserServiceError):
        delete_user(db, admin.id, acting_username="root")
    # Changing one's own password IS allowed.
    _, changes = update_user(db, admin.id, acting_username="root", new_password="a-new-long-password")
    assert changes == {"password": "reset"}
    db.close()


def test_last_admin_guard_without_env_bootstrap(monkeypatch):
    monkeypatch.delenv("DASHBOARD_USERNAME", raising=False)
    db = _db()
    admin = _mk(db, username="only-admin", role="admin")
    with pytest.raises(UserServiceError):
        update_user(db, admin.id, acting_username="someone-else", role="client")
    with pytest.raises(UserServiceError):
        delete_user(db, admin.id, acting_username="someone-else")
    # With an env bootstrap admin configured, the same operation is allowed.
    _env_admin(monkeypatch)
    user, changes = update_user(db, admin.id, acting_username="someone-else", role="client")
    assert changes["role"] == "admin → client"
    db.close()


def test_session_revocation_on_role_change_deactivate_delete(monkeypatch):
    _env_admin(monkeypatch)
    db = _db()
    user = _mk(db, username="carol", role="analyst")

    def _seed_session():
        db.add(ServerSession(token_hash=f"h-{db.query(ServerSession).count()}",
                             username="carol", role="analyst",
                             expires_at=__import__("datetime").datetime(2099, 1, 1)))
        db.commit()

    _seed_session()
    update_user(db, user.id, acting_username="root", role="client")
    db.commit()
    assert db.query(ServerSession).filter_by(username="carol").count() == 0

    _seed_session()
    update_user(db, user.id, acting_username="root", is_active=False)
    db.commit()
    assert db.query(ServerSession).filter_by(username="carol").count() == 0

    update_user(db, user.id, acting_username="root", is_active=True)
    _seed_session()
    delete_user(db, user.id, acting_username="root")
    db.commit()
    assert db.query(ServerSession).filter_by(username="carol").count() == 0
    assert db.query(User).filter_by(username="carol").first() is None
    db.close()
