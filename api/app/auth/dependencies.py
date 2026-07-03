from typing import Optional

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from .. import db as db_module
from ..services.agent_service import get_agent_metadata_by_key, update_last_seen
from .exceptions import LoginRequiredException


def require_html_auth(request: Request) -> None:
    """Dependency for HTML routes: raises LoginRequiredException (→ 302 /login)."""
    if not getattr(request.state, "user", None):
        raise LoginRequiredException()


def require_api_auth(request: Request) -> None:
    """Dependency for JSON API routes: raises 401 if unauthenticated."""
    if not getattr(request.state, "user", None):
        raise HTTPException(status_code=401, detail="Authentication required.")


def require_admin_auth(request: Request) -> None:
    """Dependency for admin-only JSON API routes: raises 403 if not admin."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")


def require_admin_html(request: Request) -> None:
    """Dependency for admin-only HTML routes: raises LoginRequiredException or 403."""
    user = getattr(request.state, "user", None)
    if not user:
        raise LoginRequiredException()
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")


def require_analyst_html(request: Request) -> None:
    """Dependency for analyst-or-admin HTML routes: raises LoginRequiredException or 403."""
    user = getattr(request.state, "user", None)
    if not user:
        raise LoginRequiredException()
    if user.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or admin access required.")


def require_analyst_auth(request: Request) -> None:
    """Allows admin or analyst roles. Used for SOAR run so analysts can submit actions for approval."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    if user.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or admin access required.")


def require_agent_key(
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    database: Session = Depends(db_module.get_db),
) -> dict:
    """Authenticate an agent-facing request by its X-Agent-Key header.

    Returns the agent metadata dict and refreshes ``last_seen`` as a side
    effect. Raises 401 for a missing or unrecognised key so both cases are
    reported uniformly to agents.
    """
    if not x_agent_key:
        raise HTTPException(status_code=401, detail="X-Agent-Key header is required.")
    agent_meta = get_agent_metadata_by_key(agent_key=x_agent_key, db=database)
    if agent_meta is None:
        raise HTTPException(status_code=401, detail="Invalid or unregistered agent key.")
    update_last_seen(agent_key=x_agent_key, db=database)
    return agent_meta
