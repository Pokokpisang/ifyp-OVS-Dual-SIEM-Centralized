import json
import re
from sqlalchemy.orm import Session
from datetime import datetime
from .. import models
from .audit_parser import AuditdParser

class RuleEngine:
    def __init__(self, db: Session):
        self.db = db

    def _run_matching_logic(self, content: str, logic: dict):
        """
        Internal helper to apply keyword and pattern matching to a string.
        Returns: (matched: bool, reason: str, tokens: list, severity: str)
        """
        matched = False
        reason = ""
        tokens = []
        severity = None

        # A. Pattern Matching (All of / Chaining) - specific logic first
        if "patterns" in logic:
            for pattern in logic["patterns"]:
                all_found = True
                temp_tokens = []
                for part in pattern.get("all_of", []):
                    if "|" in part:
                        options = part.split("|")
                        found_opt = False
                        for opt in options:
                            if opt.strip() == "": continue
                            pattern = r'(?<!\w)' + re.escape(opt.strip()) + r'(?!\w)'
                            if re.search(pattern, content, re.IGNORECASE):
                                found_opt = True
                                temp_tokens.append(opt.strip())
                                break
                        if not found_opt:
                            all_found = False
                            break
                    else:
                        pattern = r'(?<!\w)' + re.escape(part) + r'(?!\w)'
                        if not re.search(pattern, content, re.IGNORECASE):
                            all_found = False
                            break
                        else:
                            temp_tokens.append(part)
                
                if all_found and len(pattern.get("all_of", [])) > 0:
                    matched = True
                    reason = f"Pattern match: {pattern.get('name', 'unnamed')}"
                    tokens = temp_tokens
                    severity = pattern.get("severity")
                    break

        # B. Keyword Matching (Any of) - general fallback second
        if not matched and "keywords" in logic:
            for kw in logic["keywords"]:
                pattern = r'(?<!\w)' + re.escape(kw) + r'(?!\w)'
                if re.search(pattern, content, re.IGNORECASE):
                    matched = True
                    reason = f"Keyword match: {kw}"
                    tokens.append(kw)
                    break
                    
        return matched, reason, tokens, severity

    def evaluate(self, log_entry: models.Log):
        # Fetch enabled rules for this log type
        rules = self.db.query(models.DetectionRule).filter(
            models.DetectionRule.enabled == True,
            models.DetectionRule.log_type_scope == log_entry.log_type
        ).all()

        for rule in rules:
            try:
                logic = json.loads(rule.logic_json)
                matched, reason, tokens, pattern_severity = self._run_matching_logic(log_entry.message, logic)
                
                if matched:
                    severity = pattern_severity or rule.severity_default
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

        # 2. Content extraction
        content = raw_log.get("command_line") or raw_log.get("cmdline") or raw_log.get("message", "")
        if not content:
            return

        # 3. Dynamic Rule Evaluation
        rules = self.db.query(models.DetectionRule).filter(
            models.DetectionRule.enabled == True,
            models.DetectionRule.log_type_scope == "auditd"
        ).all()

        for rule in rules:
            try:
                logic = json.loads(rule.logic_json)
                matched, reason, tokens, pattern_severity = self._run_matching_logic(content, logic)

                if matched:
                    severity = pattern_severity or rule.severity_default
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
        cmd_excerpt = tokens[0][:200] if tokens else ""
        
        alert = models.Alert(
            timestamp=datetime.utcnow(),
            host=host,
            severity=severity.upper(),
            title=f"[{mitre_id}] {rule_name}",
            description=f"{reason}. Command: {cmd_excerpt}\n\nRAW_LOG: {raw_log.get('message', cmd_excerpt)}",
            source=mitre_id
        )
        self.db.add(alert)
        self.db.commit()
        print(f"[*] ALERT GENERATED: {rule_name} on {host}")
