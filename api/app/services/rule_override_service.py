"""
rule_override_service — runtime disable-switch for YAML detection rules.

YAML files (detection-as-code) stay authoritative: an override can only
DISABLE a file-enabled rule; re-enabling simply removes the runtime block.
File-disabled rules (`enabled: false` in YAML) never reach the engine and
cannot be enabled from the UI.

``get_disabled_rule_ids`` runs on the hot ingestion path (once per detection
event), so results are cached process-wide for a short TTL. Toggling
invalidates the cache immediately in this process; other workers converge
within the TTL.
"""
import logging
import time
from typing import Optional, Set

from sqlalchemy.orm import Session

from .. import models

logger = logging.getLogger("services.rule_overrides")

_CACHE_TTL_SECONDS = 30.0
_cache: Optional[Set[str]] = None
_cache_at: float = 0.0


def invalidate_cache() -> None:
    global _cache, _cache_at
    _cache = None
    _cache_at = 0.0


def get_disabled_rule_ids(db: Session) -> Set[str]:
    """Rule ids currently disabled by a runtime override (TTL-cached)."""
    global _cache, _cache_at
    now = time.monotonic()
    if _cache is not None and (now - _cache_at) < _CACHE_TTL_SECONDS:
        return _cache
    rows = (
        db.query(models.DetectionRuleOverride.rule_id)
        .filter(models.DetectionRuleOverride.enabled == False)  # noqa: E712
        .all()
    )
    _cache = {r[0] for r in rows}
    _cache_at = now
    return _cache


def set_rule_enabled(db: Session, rule_id: str, enabled: bool, *, updated_by: str) -> models.DetectionRuleOverride:
    """Upsert the runtime override for *rule_id*. Caller commits."""
    override = (
        db.query(models.DetectionRuleOverride)
        .filter(models.DetectionRuleOverride.rule_id == rule_id)
        .first()
    )
    if override is None:
        override = models.DetectionRuleOverride(rule_id=rule_id)
        db.add(override)
    override.enabled = enabled
    override.updated_by = updated_by
    invalidate_cache()
    logger.info("[RULE_OVERRIDE] %s -> %s by %s", rule_id, "enabled" if enabled else "DISABLED", updated_by)
    return override
