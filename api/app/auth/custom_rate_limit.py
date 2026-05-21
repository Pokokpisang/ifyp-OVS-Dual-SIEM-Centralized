"""
custom_rate_limit.py — Rate limit key functions.

Uses request.client.host (TCP peer address) instead of X-Forwarded-For
to prevent bypass via header spoofing (ST-040).

Deployment note: if behind a trusted reverse proxy in Docker Compose where
request.client.host is the gateway IP, rate limiting will be per-gateway
until the proxy passes X-Real-IP from a verified socket address only.
"""
from starlette.requests import Request


def client_host_key(request: Request) -> str:
    """Key function for slowapi: TCP peer address, ignores X-Forwarded-For."""
    if request.client:
        return request.client.host
    return "unknown"
