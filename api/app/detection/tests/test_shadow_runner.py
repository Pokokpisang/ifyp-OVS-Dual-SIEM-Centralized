import pytest
import os
from unittest.mock import MagicMock, patch
from app.detection.engine.shadow_runner import ShadowDetectionRunner
from app.detection.engine.yaml_detection_engine import DetectionCandidate

@pytest.fixture
def mock_engine():
    return MagicMock()

def test_shadow_mode_disabled_does_nothing(mock_engine):
    with patch.dict(os.environ, {"YAML_DETECTION_SHADOW_MODE": "false"}):
        runner = ShadowDetectionRunner(engine=mock_engine)
        runner.run({"test": "event"})
        mock_engine.evaluate_event.assert_not_called()

def test_shadow_mode_enabled_runs_engine(mock_engine):
    with patch.dict(os.environ, {"YAML_DETECTION_SHADOW_MODE": "true"}):
        mock_engine.evaluate_event.return_value = []
        runner = ShadowDetectionRunner(engine=mock_engine)
        runner.run({"test": "event"})
        mock_engine.evaluate_event.assert_called_once()

def test_engine_exception_is_caught(mock_engine):
    with patch.dict(os.environ, {"YAML_DETECTION_SHADOW_MODE": "true"}):
        mock_engine.evaluate_event.side_effect = Exception("Test Error")
        runner = ShadowDetectionRunner(engine=mock_engine)
        
        # Should not raise
        runner.run({"test": "event"})
        mock_engine.evaluate_event.assert_called_once()

def test_settings_are_passed_correctly(mock_engine):
    with patch.dict(os.environ, {
        "YAML_DETECTION_SHADOW_MODE": "true",
        "YAML_DETECTION_INCLUDE_SUPPRESSED": "false",
        "YAML_DETECTION_RETURN_UNMATCHED": "true"
    }):
        mock_engine.evaluate_event.return_value = []
        runner = ShadowDetectionRunner(engine=mock_engine)
        runner.run({"test": "event"})
        
        mock_engine.evaluate_event.assert_called_with(
            {"test": "event"},
            include_disabled=False,
            return_unmatched=True,
            include_suppressed=False
        )

def test_logging_is_called(mock_engine):
    with patch.dict(os.environ, {"YAML_DETECTION_SHADOW_MODE": "true"}):
        candidate = DetectionCandidate(
            rule_id="test_id",
            rule_name="test_name",
            matched=True,
            suppressed=False,
            severity="high",
            risk_score=75,
            base_risk_score=50,
            match_reasons=["reason1"],
            adjustment_reasons=["adj1"],
            mitre={},
            tags=[]
        )
        mock_engine.evaluate_event.return_value = [candidate]
        
        with patch("app.detection.engine.shadow_runner.logger") as mock_logger:
            runner = ShadowDetectionRunner(engine=mock_engine)
            runner.run({"test": "event"})
            
            mock_logger.info.assert_called()
            log_call = mock_logger.info.call_args[0][0]
            assert "[SHADOW_DETECTION] MATCHED" in log_call
            assert "rule_id: test_id" in log_call
            assert "severity: high" in log_call
