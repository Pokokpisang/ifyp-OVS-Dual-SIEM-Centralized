"""
routers/agents.py — Agent API endpoints.

Routes
------
GET  /install.sh              Return the bash installer script (plain text)
POST /api/agents/register     One-time token → activate agent, return agent_key
POST /api/agents/heartbeat    agent_key header → update last_seen
"""

import os
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import db
from ..services.agent_service import process_heartbeat, register_agent
from ..services import audit_service
from ..services.installer_service import generate_install_script, generate_uninstall_script
from ..services.server_address import get_server_address, normalize_server_url

router = APIRouter()

_DEFAULT_PORT = int(os.getenv("SIEM_API_PORT", "8000"))


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    hostname: str
    ip_address: str
    os: str
    arch: str


class HeartbeatResponse(BaseModel):
    status: str
    message: str


# ---------------------------------------------------------------------------
# GET /install.sh
# ---------------------------------------------------------------------------

@router.get("/install.sh", response_class=PlainTextResponse)
def get_install_script(request: Request):
    """
    Return the parameterised bash installer script.

    The script contains no hardcoded values; all configuration is injected
    at runtime via the --flags passed by the curl | bash command.
    """
    raw_server = get_server_address(request)
    port = _DEFAULT_PORT
    script = generate_install_script(server=raw_server, port=port)
    return PlainTextResponse(content=script, media_type="text/plain")


# ---------------------------------------------------------------------------
# GET /uninstall.sh
# ---------------------------------------------------------------------------

@router.get("/uninstall.sh", response_class=PlainTextResponse)
def get_uninstall_script():
    """
    Return a standalone bash script to cleanly remove the agent.
    """
    script = generate_uninstall_script()
    return PlainTextResponse(content=script, media_type="text/plain")


# ---------------------------------------------------------------------------
# POST /api/agents/register
# ---------------------------------------------------------------------------

@router.post("/api/agents/register")
def api_register_agent(
    body: RegisterRequest,
    x_agent_token: str = Header(..., alias="X-Agent-Token"),
    database: Session = Depends(db.get_db),
):
    """
    Validate the one-time registration token and activate the agent.

    On success returns the permanent ``agent_key`` the installer saves to
    ``/etc/ovs-agent/config.yaml``.

    Security
    --------
    - Token is validated by its SHA-256 hash; raw token is never stored.
    - Token is nulled from DB after first successful use.
    - Expired tokens (> 1 hour) are rejected.
    - Only ``pending`` agents can register.
    """
    raw_key = register_agent(
        token=x_agent_token,
        hostname=body.hostname,
        ip_address=body.ip_address,
        os=body.os,
        arch=body.arch,
        db=database,
    )
    # Audit the enrollment — sanitized metadata only, never the agent key/token.
    audit_service.record_audit_event(
        database,
        actor=f"agent:{body.hostname}",
        action=audit_service.AGENT_REGISTERED,
        object_type="agent",
        object_id=body.hostname,
        details={
            "hostname": body.hostname,
            "ip": body.ip_address,
            "os": body.os,
            "arch": body.arch,
        },
        commit=True,
    )
    return {"status": "registered", "agent_key": raw_key}


# ---------------------------------------------------------------------------
# POST /api/agents/heartbeat
# ---------------------------------------------------------------------------

@router.post("/api/agents/heartbeat", response_model=HeartbeatResponse)
def api_heartbeat(
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
    database: Session = Depends(db.get_db),
):
    """
    Update ``last_seen`` for the calling agent.

    The agent must send ``X-Agent-Key: <raw_key>`` on every heartbeat.
    The server validates the SHA-256 hash against the stored hash.

    Returns 401 for an unknown / invalid key.
    """
    process_heartbeat(agent_key=x_agent_key, db=database)
    return HeartbeatResponse(status="ok", message="Heartbeat received.")
