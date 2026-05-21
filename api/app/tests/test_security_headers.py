"""
test_security_headers.py — Security headers presence tests (ST-021).

TC-SH-1  All five expected security headers are present on an HTML response
TC-SH-2  CSP header value contains frame-ancestors 'none'
"""
import asyncio

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.middleware.security_headers import SecurityHeadersMiddleware


# ---------------------------------------------------------------------------
# Minimal app with SecurityHeadersMiddleware
# ---------------------------------------------------------------------------

_app = FastAPI()
_app.add_middleware(SecurityHeadersMiddleware)


@_app.get("/test-page", response_class=HTMLResponse)
def _page():
    return HTMLResponse("<html><body>OK</body></html>")


def _get_test_page() -> httpx.Response:
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.get("/test-page")

    return asyncio.get_event_loop().run_until_complete(_run())


# TC-SH-1 — All expected headers present
def test_security_headers_present():
    resp = _get_test_page()
    expected = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    for header in expected:
        assert header in resp.headers, f"Missing security header: {header}"


# TC-SH-2 — CSP frame-ancestors 'none'
def test_csp_contains_frame_ancestors_none():
    resp = _get_test_page()
    csp = resp.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp, f"CSP missing frame-ancestors 'none': {csp}"
