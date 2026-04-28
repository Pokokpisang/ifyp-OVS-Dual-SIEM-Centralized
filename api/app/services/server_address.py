"""
server_address.py — SIEM server address resolution and URL normalisation.

Priority for server address:
  1. SIEM_SERVER_ADDRESS env var (set in .env)
  2. Derived from the incoming FastAPI request.base_url

normalize_server_url() is the single source of truth for every URL
embedded in user-facing output (install command, --server arg, download URL).
No other code may concatenate host + port manually.
"""

import os
from urllib.parse import urlparse, urlunparse

from fastapi import Request


# ---------------------------------------------------------------------------
# Address resolution
# ---------------------------------------------------------------------------

def get_server_address(request: Request) -> str:
    """
    Return the raw server base address (no trailing slash).

    Prefers SIEM_SERVER_ADDRESS env var; falls back to request.base_url so the
    system works out-of-the-box on any host without configuration.
    """
    env_addr = os.getenv("SIEM_SERVER_ADDRESS", "").strip().rstrip("/")
    if env_addr:
        return env_addr
    return str(request.base_url).rstrip("/")


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------

_STANDARD_PORTS: dict[str, int] = {"http": 80, "https": 443}


def normalize_server_url(server: str, port: int) -> str:
    """
    Return a clean base URL, appending *port* only when necessary.

    Rules
    -----
    - If *server* already carries an explicit port, keep it; ignore *port*.
    - If the effective port matches the scheme default (80/http, 443/https),
      omit it from the URL so clients don't see redundant information.
    - Otherwise append the port.
    - Adds ``http://`` when *server* has no scheme so urlparse works correctly.

    Examples
    --------
    >>> normalize_server_url("http://192.168.100.10", 8000)
    'http://192.168.100.10:8000'

    >>> normalize_server_url("http://192.168.100.10:8000", 8000)
    'http://192.168.100.10:8000'          # no double-port

    >>> normalize_server_url("https://siem.example.com", 443)
    'https://siem.example.com'            # standard port omitted

    >>> normalize_server_url("https://siem.example.com", 8443)
    'https://siem.example.com:8443'
    """
    # Ensure a scheme is present so urlparse splits the host correctly
    if not server.startswith(("http://", "https://")):
        server = "http://" + server

    parsed = urlparse(server)
    scheme: str = parsed.scheme
    hostname: str = parsed.hostname or ""  # lowercase, no port
    existing_port: int | None = parsed.port  # None when not in URL

    if existing_port is not None:
        # Port already encoded in the URL — honour it, discard *port* param
        effective_port = existing_port
    else:
        effective_port = port

    # Omit port when it matches the scheme default (cleaner URLs)
    if _STANDARD_PORTS.get(scheme) == effective_port:
        netloc = hostname
    else:
        netloc = f"{hostname}:{effective_port}"

    return urlunparse((scheme, netloc, "", "", "", ""))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_LOCALHOST_VARIANTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def validate_server_address(normalized_url: str) -> tuple[bool, str | None]:
    """
    Return ``(is_valid, warning_message)``.

    A localhost address is technically valid but useless for remote agents, so
    we surface a warning rather than a hard error, allowing local testing while
    clearly communicating the limitation.
    """
    host = urlparse(normalized_url).hostname or ""
    if host in _LOCALHOST_VARIANTS:
        return False, (
            "Server address resolves to localhost. "
            "Remote agents cannot reach this address. "
            "Set SIEM_SERVER_ADDRESS in .env to your VM's real IP or hostname."
        )
    return True, None
