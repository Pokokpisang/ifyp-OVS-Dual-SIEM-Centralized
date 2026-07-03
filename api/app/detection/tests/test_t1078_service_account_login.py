import pytest
from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

RULE_ID = "linux_t1078_003_service_account_login"


@pytest.fixture
def engine():
    return YAMLDetectionEngine()


def _login_event(*, user, outcome="success", source_ip="192.168.1.50"):
    verb = "Accepted password" if outcome == "success" else "Failed password"
    return {
        "message": f"{verb} for {user} from {source_ip} port 22 ssh2",
        "log_type": "auth",
        "hostname": "prod-1",
        "event": {"outcome": outcome, "category": "authentication"},
        "service": {"name": "ssh"},
        "source": {"ip": source_ip},
        "user": {"name": user},
        "host": {"name": "prod-1"},
    }


def _t1078(engine, event):
    candidates = engine.evaluate_event(event, return_unmatched=True)
    return next((c for c in candidates if c.rule_id == RULE_ID), None)


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------

def test_t1078_service_account_internal_login_matches(engine):
    c = _t1078(engine, _login_event(user="www-data", source_ip="192.168.1.50"))
    assert c is not None
    assert c.matched is True
    assert c.suppressed is False
    assert c.risk_score == 65  # base, no external bump for RFC1918 source


def test_t1078_service_account_external_login_raises_score(engine):
    c = _t1078(engine, _login_event(user="postgres", source_ip="45.55.10.10"))
    assert c is not None
    assert c.matched is True
    assert c.suppressed is False
    assert c.risk_score == 80  # 65 + 15 external
    assert any("external" in r.lower() for r in c.adjustment_reasons)


@pytest.mark.parametrize("internal_ip", ["::1", "fe80::1", "fc00::1", "fd12::34"])
def test_t1078_ipv6_internal_source_is_not_scored_external(engine, internal_ip):
    """IPv6 loopback/link-local/ULA must not be labelled 'external' (+15)."""
    c = _t1078(engine, _login_event(user="postgres", source_ip=internal_ip))
    assert c is not None and c.matched is True
    assert c.risk_score == 65  # no external bump
    assert not any("external" in r.lower() for r in c.adjustment_reasons)


# ---------------------------------------------------------------------------
# False positives (no match)
# ---------------------------------------------------------------------------

def test_t1078_normal_user_login_does_not_match(engine):
    c = _t1078(engine, _login_event(user="jdoe"))
    assert c is None or c.matched is False


def test_t1078_root_login_does_not_match(engine):
    # root is intentionally NOT in the service-account list (deferred framing).
    c = _t1078(engine, _login_event(user="root"))
    assert c is None or c.matched is False


def test_t1078_failed_service_account_login_does_not_match(engine):
    # Failed logins are T1110's job, not this rule.
    c = _t1078(engine, _login_event(user="www-data", outcome="failure"))
    assert c is None or c.matched is False


# ---------------------------------------------------------------------------
# Suppressed (trusted-source allowlist)
# ---------------------------------------------------------------------------

def test_t1078_login_from_allowlisted_ip_is_suppressed(engine):
    c = _t1078(engine, _login_event(user="www-data", source_ip="203.0.113.200"))
    assert c is not None
    assert c.matched is True
    assert c.suppressed is True
    assert c.suppression_id == "t1078_service_login_trusted_source_allowlist"


# ---------------------------------------------------------------------------
# Malformed / required-fields guard
# ---------------------------------------------------------------------------

def test_t1078_skips_missing_user_name(engine):
    event = {
        "message": "Accepted password from 45.55.10.10 port 22 ssh2",
        "log_type": "auth",
        "event": {"outcome": "success", "category": "authentication"},
        "service": {"name": "ssh"},
        "source": {"ip": "45.55.10.10"},
        "host": {"name": "prod-1"},
    }
    # Remove any user the parser might have inferred so user.name is truly absent.
    event.pop("user", None)
    c = _t1078(engine, event)
    assert c is not None
    assert c.matched is False
    assert "user.name" in c.missing_fields


# ---------------------------------------------------------------------------
# MITRE metadata
# ---------------------------------------------------------------------------

def test_t1078_mitre_metadata(engine):
    c = _t1078(engine, _login_event(user="www-data"))
    assert c is not None and c.matched is True
    assert c.mitre.get("technique", {}).get("id") == "T1078"
    assert c.mitre.get("subtechnique", {}).get("id") == "T1078.003"
    assert c.mitre.get("tactic", {}).get("id") == "TA0005"
