"""
test_csrf.py — CSRF protection tests (ST-019).

TC-CSRF-1  Same-origin JSON request passes CSRF check
TC-CSRF-2  Cross-origin JSON request → 403
TC-CSRF-3  Absent Origin on JSON endpoint (strict mode) → 403
TC-CSRF-4  Absent Origin allowed when ALLOWED_ORIGINS bypassed via env var (non-strict)
TC-CSRF-5  Form POST with valid Referer header passes CSRF check
TC-CSRF-6  Form POST with wrong Referer → 403
TC-CSRF-7  Form POST with no Origin/Referer (strict mode) → 403
"""
import asyncio
import os

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse

from app.auth.csrf import verify_json_csrf, verify_form_csrf


# ---------------------------------------------------------------------------
# Minimal app with CSRF-protected stub endpoints
# ---------------------------------------------------------------------------

_app = FastAPI()


@_app.post("/api/json-action", dependencies=[Depends(verify_json_csrf)])
def _json_action():
    return JSONResponse({"ok": True})


@_app.post("/form-action", dependencies=[Depends(verify_form_csrf)])
def _form_action():
    return JSONResponse({"ok": True})


def _post_json(path: str, headers: dict) -> httpx.Response:
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as ac:
            return await ac.post(path, json={}, headers=headers)

    return asyncio.get_event_loop().run_until_complete(_run())


def _post_form(path: str, headers: dict) -> httpx.Response:
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as ac:
            return await ac.post(path, data={}, headers=headers)

    return asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# TC-CSRF-1 — Same-origin JSON passes
# ---------------------------------------------------------------------------

def test_same_origin_json_passes():
    os.environ["CSRF_STRICT_JSON"] = "true"
    resp = _post_json("/api/json-action", {"origin": "http://test"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TC-CSRF-2 — Cross-origin JSON → 403
# ---------------------------------------------------------------------------

def test_cross_origin_json_blocked():
    os.environ["CSRF_STRICT_JSON"] = "true"
    resp = _post_json("/api/json-action", {"origin": "http://evil.example.com"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# TC-CSRF-3 — Absent Origin in strict mode → 403
# ---------------------------------------------------------------------------

def test_absent_origin_strict_json_blocked():
    os.environ["CSRF_STRICT_JSON"] = "true"
    resp = _post_json("/api/json-action", {})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# TC-CSRF-4 — Non-strict mode allows absent Origin
# ---------------------------------------------------------------------------

def test_absent_origin_nonstrict_json_allowed():
    os.environ["CSRF_STRICT_JSON"] = "false"
    resp = _post_json("/api/json-action", {})
    assert resp.status_code == 200
    os.environ["CSRF_STRICT_JSON"] = "true"  # restore


# ---------------------------------------------------------------------------
# TC-CSRF-5 — Form POST with valid Referer passes
# ---------------------------------------------------------------------------

def test_form_post_valid_referer_passes():
    os.environ["CSRF_STRICT_FORMS"] = "true"
    resp = _post_form("/form-action", {"referer": "http://test/some-page"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TC-CSRF-6 — Form POST with bad Referer → 403
# ---------------------------------------------------------------------------

def test_form_post_bad_referer_blocked():
    os.environ["CSRF_STRICT_FORMS"] = "true"
    resp = _post_form("/form-action", {"referer": "http://attacker.example.com/page"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# TC-CSRF-7 — Form POST no Origin/Referer in strict mode → 403
# ---------------------------------------------------------------------------

def test_form_post_no_origin_no_referer_strict_blocked():
    os.environ["CSRF_STRICT_FORMS"] = "true"
    resp = _post_form("/form-action", {})
    assert resp.status_code == 403
