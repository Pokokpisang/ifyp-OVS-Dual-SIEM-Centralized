from app.detection.engine.active_runner import _get_technique_id


def test_dict_form_returns_id():
    assert _get_technique_id({"technique": {"id": "T1059.004", "name": "Unix Shell"}}) == "T1059.004"


def test_string_form_returned_as_is():
    assert _get_technique_id({"technique": "T1059"}) == "T1059"


def test_missing_technique_key_returns_empty():
    assert _get_technique_id({}) == ""


def test_empty_dict_value_returns_empty():
    assert _get_technique_id({"technique": {}}) == ""
