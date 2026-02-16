import json
import re
from sqlalchemy.orm import Session
from datetime import datetime
from .. import models

class RuleEngine:
    def __init__(self, db: Session):
        self.db = db

    def evaluate(self, log_entry: models.Log):
        # 1. Fetch enabled rules for this log type
        rules = self.db.query(models.DetectionRule).filter(
            models.DetectionRule.enabled == True,
            models.DetectionRule.log_type_scope == log_entry.log_type
        ).all()

        for rule in rules:
            try:
                logic = json.loads(rule.logic_json)
                matched = False
                reason = ""
                tokens = []

                # A. Keyword Matching (Any of)
                if "keywords" in logic:
                    for kw in logic["keywords"]:
                        if kw.lower() in log_entry.message.lower():
                            matched = True
                            reason = f"Keyword match: {kw}"
                            tokens.append(kw)
                            break
                
                # B. Pattern Matching (All of / Chaining)
                # Example: {"name": "download_pipe_exec", "all_of": ["curl", "| bash"]}
                if not matched and "patterns" in logic:
                    for pattern in logic["patterns"]:
                        all_found = True
                        temp_tokens = []
                        for part in pattern.get("all_of", []):
                            # Supports regex-like OR: "curl|wget"
                            if "|" in part:
                                options = part.split("|")
                                found_opt = False
                                for opt in options:
                                    if opt.strip() == "": continue # handle empty split
                                    if opt.strip().lower() in log_entry.message.lower():
                                        found_opt = True
                                        temp_tokens.append(opt.strip())
                                        break
                                if not found_opt:
                                    all_found = False
                                    break
                            else:
                                if part.lower() not in log_entry.message.lower():
                                    all_found = False
                                    break
                                else:
                                    temp_tokens.append(part)
                        
                        if all_found:
                            matched = True
                            reason = f"Pattern match: {pattern.get('name', 'unnamed')}"
                            tokens = temp_tokens
                            # Override severity if pattern specifies it
                            severity = pattern.get("severity", rule.severity_default)
                            break
                
                if matched:
                    self._trigger_match(rule, log_entry, reason, tokens, severity if 'severity' in locals() else rule.severity_default)

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
            description=f"{reason}. Tokens: {tokens}",
            source=rule.mitre_technique_id
        )
        self.db.add(alert)
        
        # 3. Audit Activity
        audit = models.ActivityAudit(
            timestamp_utc=datetime.utcnow(),
            actor="system",
            action="RULE_MATCHED",
            object_type="rule",
            object_id=str(rule.id),
            details=f"Matched log {log.id} from {log.host}"
        )
        self.db.add(audit)
        
        self.db.commit()
