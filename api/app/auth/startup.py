"""
Startup validation helpers for the OVS auth layer.
Safe to import without triggering any application side effects.
"""

_INSECURE_DEFAULTS = frozenset({"", "change-me-in-production"})


def validate_session_secret(secret: str) -> None:
    """Raise RuntimeError if SESSION_SECRET_KEY is absent or uses an insecure default."""
    if secret in _INSECURE_DEFAULTS:
        raise RuntimeError(
            "SESSION_SECRET_KEY is not set or uses an insecure default value. "
            "Generate a strong secret with: openssl rand -hex 32"
        )
