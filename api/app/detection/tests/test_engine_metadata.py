"""
test_engine_metadata.py — the engine_meta loader and the shipped metadata files.

These prove the correlation and SSH-brute-force engines source their alert
metadata from YAML (detection-as-code), and that the loader degrades safely.
"""
from app.detection.engine.engine_metadata import load_engine_metadata, mitre_id


def test_loader_returns_empty_for_missing_file():
    assert load_engine_metadata("does_not_exist_xyz") == {}


def test_mitre_id_helper_falls_back():
    assert mitre_id({}, "tactic", "TA0000") == "TA0000"
    assert mitre_id({"mitre": {"technique": {"id": "T9999"}}}, "technique", "x") == "T9999"


def test_correlation_metadata_values():
    meta = load_engine_metadata("correlation_download_execution")
    assert meta["rule_id"] == "linux_t1059_download_then_shell_execution"
    assert meta["rule_name"] == "Network Script Download Followed by Shell Execution"
    assert meta["severity"] == "high"
    assert meta["risk_score"] == 70
    assert mitre_id(meta, "tactic", "?") == "TA0002"
    assert mitre_id(meta, "technique", "?") == "T1059.004"


def test_ssh_bruteforce_metadata_values():
    meta = load_engine_metadata("ssh_bruteforce_threshold")
    assert meta["rule_id"] == "linux_t1110_ssh_bruteforce"
    assert meta["rule_name"] == "SSH Brute Force Authentication Failures"
    assert meta["severity"] == "medium"
    assert meta["risk_score"] == 45
    assert mitre_id(meta, "tactic", "?") == "TA0006"
    assert mitre_id(meta, "technique", "?") == "T1110"
