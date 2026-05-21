from fastapi import HTTPException, Request

from .exceptions import LoginRequiredException


def require_html_auth(request: Request) -> None:
    """Dependency for HTML routes: raises LoginRequiredException (→ 302 /login)."""
    if not request.session.get("authenticated"):
        raise LoginRequiredException()


def require_api_auth(request: Request) -> None:
    """Dependency for JSON API routes: raises 401 if unauthenticated."""
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Authentication required.")
