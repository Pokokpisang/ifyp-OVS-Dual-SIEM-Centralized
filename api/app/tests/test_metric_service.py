"""
test_metric_service.py — system-health rule evaluation (extracted from the
metrics ingest router). Pure unit tests with a dispatching mock DB; create_alert
is patched so we assert on the AlertSpec and call flags rather than the DB.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app import models
from app.services import metric_service
from app.services.metric_service import (
    _threshold_breached,
    evaluate_health_rules,
)


def _metric(cpu=10.0, ram=20.0, host="host-1", net_in=0, net_out=0):
    return SimpleNamespace(
        cpu_percent=cpu, ram_percent=ram, host=host,
        net_in_bytes=net_in, net_out_bytes=net_out,
    )


def _rule(metric_name="cpu", operator=">", threshold=80.0, **kw):
    defaults = dict(
        metric_name=metric_name, operator=operator, threshold_value=threshold,
        severity="HIGH", rule_name="High CPU", rule_id="hr-cpu",
        detection_engine="MetricEngine", last_triggered=None,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _make_db(rules, recent_alert=None):
    """Dispatch db.query() by model: rules for SystemHealthRule, cooldown row
    for Alert."""
    db = MagicMock()

    def query_side(model):
        q = MagicMock()
        if model is models.SystemHealthRule:
            q.filter.return_value.all.return_value = rules
        elif model is models.Alert:
            q.filter.return_value.first.return_value = recent_alert
        return q

    db.query.side_effect = query_side
    return db


def test_threshold_breached_operators():
    assert _threshold_breached(90, ">", 80) is True
    assert _threshold_breached(70, ">", 80) is False
    assert _threshold_breached(5, "<", 10) is True
    assert _threshold_breached(15, "<", 10) is False
    assert _threshold_breached(90, "==", 80) is False  # unsupported op


@patch("app.services.metric_service.create_alert")
def test_cpu_breach_creates_alert_without_soar(mock_create):
    rule = _rule(metric_name="cpu", operator=">", threshold=80.0)
    db = _make_db([rule])

    evaluate_health_rules(db, _metric(cpu=95.0), {"agent_id": "a1"})

    mock_create.assert_called_once()
    args, kwargs = mock_create.call_args
    spec = args[1]
    assert spec.rule_id == "hr-cpu"
    assert spec.risk_score == 20
    assert spec.agent_id == "a1"
    assert kwargs["trigger_soar"] is False
    assert kwargs["commit"] is False
    assert rule.last_triggered is not None
    db.commit.assert_called_once()


@patch("app.services.metric_service.create_alert")
def test_below_threshold_creates_nothing(mock_create):
    db = _make_db([_rule(threshold=80.0)])
    evaluate_health_rules(db, _metric(cpu=10.0), {"agent_id": "a1"})
    mock_create.assert_not_called()


@patch("app.services.metric_service.create_alert")
def test_cooldown_suppresses_duplicate(mock_create):
    db = _make_db([_rule(threshold=80.0)], recent_alert=MagicMock())
    evaluate_health_rules(db, _metric(cpu=99.0), {"agent_id": "a1"})
    mock_create.assert_not_called()


@patch("app.services.metric_service.compute_metrics_summary", return_value={"net_in_rate": 200_000_000.0})
@patch("app.services.metric_service.create_alert")
def test_net_in_rate_path(mock_create, mock_summary):
    rule = _rule(metric_name="net_in", operator=">", threshold=100_000_000.0,
                 rule_id="hr-net", rule_name="High Net In")
    db = _make_db([rule])

    evaluate_health_rules(db, _metric(host="host-1"), {"agent_id": "a1"})

    mock_create.assert_called_once()
    spec = mock_create.call_args[0][1]
    assert spec.detection_metadata["unit"] == "B/s"
    assert spec.detection_metadata["observed_value"] == 200_000_000.0
