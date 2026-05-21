"""
test_session_store.py — Unit tests for server-side session store (ST-010, ST-041).

TC-SS-1  create_session returns a non-empty raw token
TC-SS-2  validate_session returns user dict for a valid token
TC-SS-3  delete_session causes validate_session to return None (replay-after-logout)
TC-SS-4  validate_session returns None for a completely unknown token
TC-SS-5  purge_expired_sessions removes expired rows only
TC-SS-6  token_hash stored in DB is sha256(raw_token), never the raw token
TC-SS-7  validate_session respects SESSION_MAX_AGE_SECONDS env var
TC-SS-8  create_session accepts role and validate_session returns it
"""
import hashlib

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, ServerSession
from app.auth.session_store import (
    create_session,
    delete_session,
    purge_expired_sessions,
    validate_session,
)


@pytest.fixture(scope="module")
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    yield s
    s.close()


# TC-SS-1
def test_create_session_returns_nonempty_token(db):
    token = create_session("alice", "admin", db)
    assert isinstance(token, str)
    assert len(token) >= 32


# TC-SS-2
def test_validate_session_returns_user_dict(db):
    token = create_session("alice", "admin", db)
    result = validate_session(token, db)
    assert result is not None
    assert result["username"] == "alice"
    assert result["role"] == "admin"


# TC-SS-3 — replay-after-logout must fail (ST-010)
def test_delete_session_prevents_replay(db):
    token = create_session("bob", "client", db)
    assert validate_session(token, db) is not None
    delete_session(token, db)
    assert validate_session(token, db) is None


# TC-SS-4
def test_validate_unknown_token_returns_none(db):
    assert validate_session("completely-unknown-token", db) is None


# TC-SS-5
def test_purge_expired_removes_only_expired_rows(db):
    from datetime import datetime, timedelta

    # Create a fresh session first (so it survives the purge)
    fresh_token = create_session("survivor", "admin", db)

    # Insert an expired session row directly (after fresh session, to avoid being purged by create_session)
    expired = ServerSession(
        token_hash="expired_hash_unique_456",
        username="expired_user",
        role="admin",
        created_at=datetime.utcnow() - timedelta(hours=2),
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )
    db.add(expired)
    db.commit()

    # Now purge: should remove the expired row
    removed = purge_expired_sessions(db)
    assert removed >= 1, f"Expected at least 1 row purged, got {removed}"

    # Fresh session must still be valid
    assert validate_session(fresh_token, db) is not None
    # Expired row must be gone
    assert (
        db.query(ServerSession)
        .filter(ServerSession.token_hash == "expired_hash_unique_456")
        .first()
    ) is None


# TC-SS-6 — DB must store sha256(raw_token), not the raw token
def test_db_stores_hash_not_raw_token(db):
    token = create_session("charlie", "admin", db)
    expected_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.query(ServerSession).filter(ServerSession.token_hash == expected_hash).first()
    assert row is not None, "Row should exist with sha256 hash"
    assert token not in (row.token_hash or "")


# TC-SS-7 — SESSION_MAX_AGE_SECONDS controls expiry
def test_session_max_age_env_var_respected(db):
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("SESSION_MAX_AGE_SECONDS", "3600")
        token = create_session("dave", "admin", db)
        expected_hash = hashlib.sha256(token.encode()).hexdigest()
        row = db.query(ServerSession).filter(ServerSession.token_hash == expected_hash).first()
        assert row is not None
        from datetime import datetime
        delta = (row.expires_at - row.created_at).total_seconds()
        assert abs(delta - 3600) < 5


# TC-SS-8 — role is preserved through create → validate round-trip
def test_create_session_preserves_role(db):
    token = create_session("eve", "client", db)
    result = validate_session(token, db)
    assert result is not None
    assert result["role"] == "client"
