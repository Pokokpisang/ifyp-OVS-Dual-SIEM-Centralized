# Detection Module

This module contains the Detection-as-Code architecture for the SIEM.
It is responsible for loading rules, evaluating security events, and generating alerts.

## Structure

- `engine/`: The core logic for rule evaluation and alert generation.
- `schemas/`: Data models for rules, events, and alerts.
- `rules/`: Modular detection rules (YAML/Python).
- `tuning/`: Suppression and exception configurations.
- `tests/`: Unit and integration tests for detection logic.
