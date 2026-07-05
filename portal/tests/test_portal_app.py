"""
test_portal_app.py — client portal app (Phase 4C).

The SOC API is mocked at the soc_client boundary; the two-server
integration is exercised separately by the repo's smoke script.
Covers: page rendering from portal API payloads, the optional password
gate, and both SOC-failure states (outage / rejected key).
"""
import asyncio
import os
from unittest.mock import patch

import httpx

from app import main as portal_main
from app import soc_client

SUMMARY = {
    "client": {"name": "Northwind Cloud", "status": "active"},
    "agents": {"total": 2, "online": 1, "offline": 1, "pending": 0},
    "alerts": {"total": 5, "open": 2, "last_24h": 1, "by_severity": {"HIGH": 3, "LOW": 2}},
    "generated_at": "2026-07-05 10:00:00",
}
AGENTS = {"agents": [{
    "name": "web-01", "hostname": "web-01.lab", "ip_address": "10.0.0.1",
    "os": "Linux Ubuntu", "status": "active", "last_seen": "2026-07-05 10:00:00",
    "monitored_since": "2026-06-01",
}]}
ALERTS = {"alerts": [{
    "id": 7, "timestamp": "2026-07-05 09:00:00", "severity": "HIGH",
    "title": "SSH brute force detected", "description": "12 failed logins",
    "host": "web-01.lab", "mitre_tactic": "TA0006", "mitre_technique": "T1110",
    "risk_score": 70,
}], "total": 1, "page": 1, "page_count": 1}
POSTURE = {"window_days": 30, "total_alerts": 5, "by_severity": {"HIGH": 3},
           "top_techniques": [{"technique": "T1110", "count": 3}],
           "top_hosts": [{"host": "web-01.lab", "count": 4}]}


def _get(path, cookies=None):
    async def _run():
        transport = httpx.ASGITransport(app=portal_main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://portal",
                                     cookies=cookies, follow_redirects=False) as c:
            return await c.get(path)
    return asyncio.get_event_loop().run_until_complete(_run())


def _post(path, data):
    async def _run():
        transport = httpx.ASGITransport(app=portal_main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://portal",
                                     follow_redirects=False) as c:
            return await c.post(path, data=data)
    return asyncio.get_event_loop().run_until_complete(_run())


def _no_gate(monkeypatch):
    monkeypatch.delenv("PORTAL_PASSWORD", raising=False)


def test_pages_render_from_portal_payloads(monkeypatch):
    _no_gate(monkeypatch)
    with patch.object(soc_client, "get_summary", return_value=SUMMARY), \
         patch.object(soc_client, "get_agents", return_value=AGENTS), \
         patch.object(soc_client, "get_alerts", return_value=ALERTS), \
         patch.object(soc_client, "get_security_summary", return_value=POSTURE):
        r = _get("/")
        assert r.status_code == 200 and "Northwind Cloud" in r.text and "Client view" in r.text
        r = _get("/agents")
        assert r.status_code == 200 and "web-01.lab" in r.text and "online" in r.text
        r = _get("/events")
        assert r.status_code == 200 and "SSH brute force detected" in r.text and "T1110" in r.text
        r = _get("/posture?days=30")
        assert r.status_code == 200 and "web-01.lab" in r.text


def test_password_gate(monkeypatch):
    monkeypatch.setenv("PORTAL_PASSWORD", "letmein-portal-1")
    r = _get("/")
    assert r.status_code == 302 and r.headers["location"] == "/login"

    r = _post("/login", {"password": "wrong"})
    assert r.status_code == 200 and "Incorrect password" in r.text

    async def _flow():
        transport = httpx.ASGITransport(app=portal_main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://portal",
                                     follow_redirects=False) as c:
            r = await c.post("/login", data={"password": "letmein-portal-1"})
            assert r.status_code == 303
            with patch.object(soc_client, "get_summary", return_value=SUMMARY):
                r = await c.get("/")
                assert r.status_code == 200 and "Northwind Cloud" in r.text
            r = await c.post("/logout")
            assert r.status_code == 303
            r = await c.get("/")
            assert r.status_code == 302  # gate again after logout
    asyncio.get_event_loop().run_until_complete(_flow())


def test_soc_failure_states(monkeypatch):
    _no_gate(monkeypatch)
    with patch.object(soc_client, "get_summary", side_effect=soc_client.SOCUnavailableError("boom")):
        r = _get("/")
        assert r.status_code == 200 and "Security server unreachable" in r.text
        assert "still being monitored" in r.text
    with patch.object(soc_client, "get_summary", side_effect=soc_client.SOCUnauthorizedError("revoked")):
        r = _get("/")
        assert r.status_code == 200 and "Portal access problem" in r.text
        assert "contact your security operations provider" in r.text


def test_soc_client_requires_config(monkeypatch):
    monkeypatch.delenv("SOC_API_URL", raising=False)
    monkeypatch.delenv("CLIENT_API_KEY", raising=False)
    try:
        soc_client.get_summary()
        assert False, "should have raised"
    except soc_client.SOCUnauthorizedError:
        pass
