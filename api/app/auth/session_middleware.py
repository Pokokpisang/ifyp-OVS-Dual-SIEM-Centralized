"""
session_middleware.py — Validates server-side session on every request.

Must be added AFTER SessionMiddleware in main.py so that request.session
is already populated when this middleware runs.

On each request:
  1. Check if path is exempt (agent ingestion, static, health, login, agent API)
  2. Read request.session.get("session_token")
  3. Validate against server_sessions table (sha256 hash lookup)
  4. Set request.state.user = {"username": ..., "role": ...} on valid session
  5. Set request.state.user = None if invalid/missing/expired

Auth dependencies check request.state.user — their signatures are unchanged.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .session_store import validate_session
from ..db import SessionLocal

# Prefix exemptions: any path starting with these is exempt (agent ingestion, static)
_EXEMPT_PREFIXES = ("/ingest/", "/static/")

# Exact-match exemptions: only these specific paths are exempt
_EXEMPT_EXACT = frozenset({
    "/health",
    "/login",
    "/api/agents/register",
    "/api/agents/heartbeat",
    "/api/agent/rules",
})


class ServerSessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.user = None
        path = request.url.path
        exempt = (
            any(path.startswith(p) for p in _EXEMPT_PREFIXES)
            or path in _EXEMPT_EXACT
        )
        if not exempt:
            raw_token = request.session.get("session_token")
            if raw_token:
                db = SessionLocal()
                try:
                    request.state.user = validate_session(raw_token, db)
                finally:
                    db.close()
        return await call_next(request)
