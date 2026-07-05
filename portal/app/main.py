"""
OVS Client Portal — standalone read-only viewer for one tenant.

Runs in its own environment (NOT the SOC server). All data comes from the
SOC's /api/portal endpoints via soc_client; there is no database, no agent
registration, and no way to mutate SOC state from here.

Env:
  SOC_API_URL         SOC server base URL
  CLIENT_API_KEY      per-client portal key (issued by the SOC admin)
  PORTAL_PASSWORD     optional shared password gate for portal users;
                      leave unset ONLY if the portal is otherwise protected
                      (private network / operator SSO in front)
  PORTAL_SECRET_KEY   session-cookie signing secret (auto-generated if unset;
                      sessions then reset on restart)
"""
import hmac
import os
import secrets
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import soc_client

app = FastAPI(title="OVS Client Portal", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("PORTAL_SECRET_KEY") or secrets.token_urlsafe(32),
    session_cookie="portal_session",
    same_site="lax",
    https_only=os.getenv("PORTAL_COOKIE_SECURE", "false").lower() == "true",
    max_age=8 * 3600,
)

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _gate_enabled() -> bool:
    return bool(os.getenv("PORTAL_PASSWORD"))


def _authed(request: Request) -> bool:
    return not _gate_enabled() or request.session.get("authed") is True


def _render(request: Request, template: str, **ctx):
    return templates.TemplateResponse(template, {
        "request": request,
        "gate_enabled": _gate_enabled(),
        **ctx,
    })


def _guarded(request: Request, template: str, fetch, **extra):
    """Auth-gate + SOC fetch + friendly error states, shared by all pages."""
    if not _authed(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        data = fetch()
    except soc_client.SOCUnauthorizedError as exc:
        return _render(request, "error.html", kind="key", detail=str(exc))
    except soc_client.SOCUnavailableError as exc:
        return _render(request, "error.html", kind="outage", detail=str(exc))
    return _render(request, template, **data, **extra)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if _authed(request):
        return RedirectResponse(url="/", status_code=302)
    return _render(request, "login.html", error=None)


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    expected = os.getenv("PORTAL_PASSWORD", "")
    if expected and hmac.compare_digest(password, expected):
        request.session["authed"] = True
        return RedirectResponse(url="/", status_code=303)
    return _render(request, "login.html", error="Incorrect password.")


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def overview(request: Request):
    return _guarded(request, "overview.html", lambda: {"summary": soc_client.get_summary()},
                    active="overview")


@app.get("/agents", response_class=HTMLResponse)
def agents(request: Request):
    return _guarded(request, "agents.html", lambda: soc_client.get_agents(), active="agents")


@app.get("/events", response_class=HTMLResponse)
def events(request: Request, severity: str = "", page: int = 1):
    return _guarded(
        request, "events.html",
        lambda: soc_client.get_alerts(severity=severity, page=max(page, 1)),
        active="events", severity=severity,
    )


@app.get("/posture", response_class=HTMLResponse)
def posture(request: Request, days: int = 30):
    days = days if days in (7, 30, 90) else 30
    return _guarded(
        request, "posture.html",
        lambda: {"posture": soc_client.get_security_summary(days=days)},
        active="posture", days=days,
    )
