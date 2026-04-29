"""
Detection engine orchestrator.

Future responsibility:
- Receive normalized security events
- Load active rules
- Evaluate rules
- Apply risk scoring
- Apply suppressions
- Return alert or suppressed result
"""
import json
from datetime import datetime
from sqlalchemy.orm import Session
from ... import models
from .audit_parser import AuditdParser
from .rule_evaluator import normalize_logic, match_conditions, exclude_conditions
from .suppressions import GLOBAL_EXCLUSIONS
from .shadow_runner import get_shadow_runner

class RuleEngine:
    """
    Temporary RuleEngine class for backward compatibility.
    This will be evolved into a more modular DetectionEngine.
    """
    GLOBAL_EXCLUSIONS = GLOBAL_EXCLUSIONS

    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def normalize_logic(logic: dict) -> dict:
        return normalize_logic(logic)

    def _match_conditions(self, content: str, match_logic: dict):
        return match_conditions(content, match_logic)

    def _exclude_conditions(self, content: str, raw_log: dict, exclude_logic: dict):
        return exclude_conditions(content, raw_log, exclude_logic)

    def evaluate(self, log_entry: models.Log):
        # Fetch enabled rules for this log type
        rules = self.db.query(models.DetectionRule).filter(
            models.DetectionRule.enabled == True,
            models.DetectionRule.rule_type == "server",
            models.DetectionRule.log_type_scope == log_entry.log_type
        ).all()

        for rule in rules:
            try:
                raw_logic = json.loads(rule.logic_json)
                logic = self.normalize_logic(raw_logic)
                
                content = log_entry.message or ""
                matched, match_reason, tokens, pattern_severity = self._match_conditions(content, logic["match"])
                
                if matched:
                    excluded, exclude_reason = self._exclude_conditions(content, {}, logic["exclude"])
                    if excluded:
                        continue
                        
                    severity = pattern_severity or logic.get("alert", {}).get("severity") or rule.severity_default
                    alert_msg = logic.get("alert", {}).get("message")
                    reason = f"{match_reason}. {alert_msg}" if alert_msg else match_reason
                    self._trigger_match(rule, log_entry, reason, tokens, severity)

            except Exception as e:
                print(f"Error evaluating rule {rule.name}: {e}")

    def _trigger_match(self, rule, log, reason, tokens, severity):
        # 1. Record Rule Match
        match = models.RuleMatch(
            matched_at_utc=datetime.utcnow(),
            rule_id=rule.id,
            log_id=log.id,
            host=log.host,
            severity=severity,
            match_reason=reason,
            matched_tokens=json.dumps(tokens),
            message_excerpt=log.message[:500]
        )
        self.db.add(match)

        # 2. Generate Alert
        alert = models.Alert(
            timestamp=datetime.utcnow(),
            host=log.host,
            severity=severity,
            title=f"Detection: {rule.name}",
            description=f"{reason}. Tokens: {tokens}\n\nRAW_LOG: {log.message}",
            source=rule.mitre_technique_id
        )
        self.db.add(alert)
        self.db.commit()

    def evaluate_raw(self, raw_log: dict):
        # 1. Normalize auditd logs
        if raw_log.get("log_type") == "auditd" or "type=" in raw_log.get("message", ""):
            raw_log = AuditdParser.normalize_log(raw_log)

        # 1b. Shadow Mode YAML Evaluation (Non-invasive)
        get_shadow_runner().run(raw_log)

        # 2. Content extraction
        content = raw_log.get("command_line") or raw_log.get("cmdline") or raw_log.get("message", "")
        if not content:
            return

        # 3. Global Exclusions (Whitelist)
        content_lower = content.lower()
        for exclusion in self.GLOBAL_EXCLUSIONS:
            if exclusion.lower() in content_lower:
                return

        # 4. Dynamic Rule Evaluation
        rules = self.db.query(models.DetectionRule).filter(
            models.DetectionRule.enabled == True,
            models.DetectionRule.rule_type == "server",
            models.DetectionRule.log_type_scope == "auditd"
        ).all()

        for rule in rules:
            try:
                raw_logic = json.loads(rule.logic_json)
                logic = self.normalize_logic(raw_logic)
                
                matched, match_reason, tokens, pattern_severity = self._match_conditions(content, logic["match"])

                if matched:
                    excluded, exclude_reason = self._exclude_conditions(content, raw_log, logic["exclude"])
                    if excluded:
                        continue
                        
                    severity = pattern_severity or logic.get("alert", {}).get("severity") or rule.severity_default
                    alert_msg = logic.get("alert", {}).get("message")
                    reason = f"{match_reason}. {alert_msg}" if alert_msg else match_reason
                    
                    self._trigger_raw_match(
                        rule_name=rule.name,
                        mitre_id=rule.mitre_technique_id,
                        raw_log=raw_log,
                        reason=reason,
                        tokens=tokens,
                        severity=severity
                    )
            except Exception as e:
                print(f"Error evaluating raw rule {rule.name}: {e}")
    
    def _trigger_raw_match(self, rule_name, mitre_id, raw_log, reason, tokens, severity):
        host = raw_log.get("hostname", raw_log.get("host", "unknown"))
        
        # Use the enriched command_line if available
        display_cmd = raw_log.get("command_line", "")
        if not display_cmd and tokens:
            display_cmd = tokens[0]
            
        alert = models.Alert(
            timestamp=datetime.utcnow(),
            host=host,
            severity=severity.upper(),
            title=f"[{mitre_id}] {rule_name}",
            description=f"{reason}. Command: {display_cmd}\n\nRAW_LOG: {raw_log.get('message')}",
            source=mitre_id
        )
        self.db.add(alert)
        self.db.commit()
        print(f"[*] ALERT GENERATED: {rule_name} on {host}")

# TODO: Implement the DetectionEngine class that coordinates the detection pipeline.
