"""
Shared detection-test fixtures.
"""
import json
from pathlib import Path

import pytest

from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    """Load a synthetic event fixture by file stem (without .json)."""
    path = _FIXTURES_DIR / f"{name}.json"
    with open(path, "r") as f:
        return json.load(f)


@pytest.fixture
def yaml_engine() -> YAMLDetectionEngine:
    """A YAMLDetectionEngine loading the real shipped rules."""
    return YAMLDetectionEngine()


@pytest.fixture
def fixture_loader():
    return load_fixture
