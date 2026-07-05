"""
soc_client — the portal's ONLY data source: the SOC server's read-only
/api/portal endpoints, authenticated with this deployment's client key.

Env (read at call time so tests/deploys can change them without reload):
  SOC_API_URL      e.g. https://soc.example.com  (no trailing slash needed)
  CLIENT_API_KEY   ovsc_… key issued by the SOC admin at /clients/{id}

The portal holds no database and can never mutate SOC state — the key only
works on GET /api/portal/* by construction (enforced server-side).
"""
import os

import httpx

_TIMEOUT_SECONDS = 8


class SOCUnavailableError(Exception):
    """SOC API unreachable or erroring — render the friendly outage state."""


class SOCUnauthorizedError(Exception):
    """Key missing/revoked or client suspended — render the key-problem state."""


def _get(path: str, params: dict | None = None) -> dict:
    base = os.getenv("SOC_API_URL", "").rstrip("/")
    key = os.getenv("CLIENT_API_KEY", "")
    if not base or not key:
        raise SOCUnauthorizedError("SOC_API_URL / CLIENT_API_KEY not configured")
    try:
        response = httpx.get(
            f"{base}{path}",
            params=params,
            headers={"X-Client-Key": key},
            timeout=_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise SOCUnavailableError(str(exc))
    if response.status_code == 401:
        raise SOCUnauthorizedError("Portal key rejected (revoked, rotated, or client suspended)")
    if response.status_code >= 400:
        raise SOCUnavailableError(f"SOC API returned HTTP {response.status_code}")
    return response.json()


def get_summary() -> dict:
    return _get("/api/portal/summary")


def get_agents() -> dict:
    return _get("/api/portal/agents")


def get_alerts(severity: str = "", page: int = 1) -> dict:
    params = {"page": page}
    if severity:
        params["severity"] = severity
    return _get("/api/portal/alerts", params)


def get_security_summary(days: int = 30) -> dict:
    return _get("/api/portal/security-summary", {"days": days})
