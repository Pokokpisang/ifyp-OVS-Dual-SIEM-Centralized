# Detection Engine

The detection engine orchestrates the evaluation of security events against loaded rules.

## Components

- `detection_engine.py`: Orchestrator.
- `rule_loader.py`: Loads rules from files/DB.
- `rule_evaluator.py`: Core matching logic.
- `risk_scoring.py`: Calculates alert severity and risk.
- `suppressions.py`: Handles false positive filtering.
- `mitre_mapper.py`: Maps detections to MITRE ATT&CK.
