from fastapi import HTTPException, Request

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


def require_analyst_auth(request: Request) -> None:
    """Allows admin or analyst roles. Used for SOAR run so analysts can submit actions for approval."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    if user.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or admin access required.")
