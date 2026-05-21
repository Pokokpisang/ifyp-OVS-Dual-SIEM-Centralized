"""
csrf.py — Origin-based CSRF protection for dashboard state-changing endpoints.

Policy:
  - For JSON API endpoints (verify_json_csrf):
      * If Origin is present: must match server origin or ALLOWED_ORIGINS.
      * If Origin is absent: rejected by default (CSRF_STRICT_JSON=true).
        Set CSRF_STRICT_JSON=false in .env only for local curl-based dev testing.
  - For HTML form endpoints (verify_form_csrf):
      * Checks Origin, falls back to Referer.
      * Absent both: rejected when CSRF_STRICT_FORMS=true (default).

Agent ingestion endpoints (/ingest/log, POST /api/metrics) use X-Agent-Key
and are explicitly NOT subject to these checks.

Env vars:
  ALLOWED_ORIGINS    — comma-separated list of allowed cross-origins (empty = same-origin only)
  CSRF_STRICT_JSON   — "true" (default) | "false" (dev only, allows missing Origin)
  CSRF_STRICT_FORMS  — "true" (default) | "false" (dev only, allows missing Origin/Referer)
"""
import os
from typing import Set

from fastapi import HTTPException, Request


def _allowed_origins() -> Set[str]:
    raw = os.getenv("ALLOWED_ORIGINS", "")
    return {o.strip() for o in raw.split(",") if o.strip()}


def verify_json_csrf(request: Request) -> None:
    """Dependency for session-authenticated JSON state-changing endpoints."""
    origin = request.headers.get("origin")
    server_origin = f"{request.url.scheme}://{request.url.netloc}"
    allowed = _allowed_origins()

    if origin is None:
        strict = os.getenv("CSRF_STRICT_JSON", "true").lower() == "true"
        if strict:
            raise HTTPException(
                status_code=403,
                detail="CSRF check failed: Origin header required.",
            )
        return

    if origin == server_origin or origin in allowed:
        return

    raise HTTPException(
        status_code=403,
        detail="CSRF check failed: Origin not allowed.",
    )


def verify_form_csrf(request: Request) -> None:
    """Dependency for HTML form POST endpoints (e.g. POST /logout)."""
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    server_origin = f"{request.url.scheme}://{request.url.netloc}"
    allowed = _allowed_origins()

    if origin:
        if origin == server_origin or origin in allowed:
            return
        raise HTTPException(
            status_code=403,
            detail="CSRF check failed: Origin not allowed.",
        )

    if referer:
        if referer.startswith(server_origin) or any(
            referer.startswith(o) for o in allowed
        ):
            return
        raise HTTPException(
            status_code=403,
            detail="CSRF check failed: Referer not allowed.",
        )

    strict = os.getenv("CSRF_STRICT_FORMS", "true").lower() == "true"
    if strict:
        raise HTTPException(
            status_code=403,
            detail="CSRF check failed: Origin/Referer absent.",
        )
