# Detection Engine Scripts

This directory contains utility scripts for testing and managing the YAML-based detection engine.

## Manual Rule Testing

The `test_yaml_detection_engine.py` script allows you to evaluate a normalized event against the loaded YAML rules without writing anything to the database or affecting the live alert pipeline.

### Usage

Run with the default built-in sample event:
```bash
python3 scripts/test_yaml_detection_engine.py
```

Run with a specific event JSON file:
```bash
python3 scripts/test_yaml_detection_engine.py samples/events/suspicious_shell_event.json
```

Include unmatched rules in the output (debug mode):
```bash
python3 scripts/test_yaml_detection_engine.py --unmatched
```

### Sample Events
Sample event files are located in `samples/events/`.

- `suspicious_shell_event.json`: Triggers T1059 rule with increased risk.
- `benign_build_event.json`: Demonstrates suppression logic.
- `lsof_check_event.json`: Demonstrates Linux-specific suppressions.
- `unmatched_event.json`: Harmless event that should not trigger rules.
