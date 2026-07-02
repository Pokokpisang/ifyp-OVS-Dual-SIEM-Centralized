"""
test_alert_service.py — unit tests for the shared alert factory.

create_alert is the single path all detection engines and the system-health
router use to persist an Alert, so these tests pin down field mapping, dedup
short-circuiting, commit control, and SOAR triggering.
"""
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app import models
from app.services.alert_service import (
    AlertSpec,
    create_alert,
    get_actor_username,
)


def _db_no_dupe():
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    return db


def _spec(**kw):
    defaults = dict(
        host="host-1",
        severity="HIGH",
        title="[rule-1] Test",
        description="desc",
        detection_engine="YAML",
        detection_metadata={"a": 1},
        source="T1059",
        agent_id="agent-1",
        rule_id="rule-1",
        rule_name="Test",
        risk_score=70,
        mitre_tactic="TA0002",
        mitre_technique="T1059",
    )
    defaults.update(kw)
    return AlertSpec(**defaults)


@patch("app.services.alert_service.trigger_soar_auto_run_for_alert")
def test_fields_mapped_and_metadata_json_encoded(mock_soar):
    db = _db_no_dupe()
    alert = create_alert(db, _spec())

    db.add.assert_called_once()
    db.commit.assert_called_once()
    added = db.add.call_args[0][0]
    assert isinstance(added, models.Alert)
    assert added.severity == "HIGH"
    assert added.detection_engine == "YAML"
    assert added.risk_score == 70
    assert added.mitre_technique == "T1059"
    # metadata is JSON-encoded, not a raw dict
    assert json.loads(added.detection_metadata) == {"a": 1}
    assert alert is added


@patch("app.services.alert_service.trigger_soar_auto_run_for_alert")
def test_dedup_short_circuits_without_writing(mock_soar):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = MagicMock()  # existing row

    result = create_alert(db, _spec(dedup_key="yaml:dupe"))

    assert result is None
    db.add.assert_not_called()
    db.commit.assert_not_called()
    mock_soar.assert_not_called()


@patch("app.services.alert_service.trigger_soar_auto_run_for_alert")
def test_trigger_soar_false_skips_auto_run(mock_soar):
    db = _db_no_dupe()
    create_alert(db, _spec(), trigger_soar=False)
    mock_soar.assert_not_called()


@patch("app.services.alert_service.trigger_soar_auto_run_for_alert")
def test_commit_false_defers_commit_and_soar(mock_soar):
    db = _db_no_dupe()
    alert = create_alert(db, _spec(), commit=False)

    db.add.assert_called_once()
    db.commit.assert_not_called()   # caller owns the commit
    mock_soar.assert_not_called()   # cannot fire before commit assigns an id
    assert alert is not None


@patch("app.services.alert_service.trigger_soar_auto_run_for_alert")
def test_soar_fired_with_committed_alert_id(mock_soar):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None

    def capture_add(obj):
        obj.id = 42

    db.add.side_effect = capture_add
    create_alert(db, _spec())
    mock_soar.assert_called_once_with(42, db)


def test_get_actor_username_reads_session():
    req = SimpleNamespace(state=SimpleNamespace(user={"username": "alice"}))
    assert get_actor_username(req) == "alice"


def test_get_actor_username_falls_back():
    req = SimpleNamespace(state=SimpleNamespace(user=None))
    assert get_actor_username(req, default="analyst") == "analyst"
