import json
import re
import ipaddress
from sqlalchemy.orm import Session
from datetime import datetime
from .. import models
from .audit_parser import AuditdParser

class RuleEngine:
    # Global list of substrings that, if found in a command, will skip alert generation.
    # Useful for health checks and known SIEM internal processes.
    GLOBAL_EXCLUSIONS = [
        "pg_isready",
        "/_cluster/health",
        "api/agent/rules",
        "docker-gen",
        "container_health_check"
    ]

    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def normalize_logic(logic: dict) -> dict:
        if "match" not in logic:
            match_block = {}
            if "keywords" in logic:
                match_block["keywords_any"] = logic["keywords"]
            if "patterns" in logic:
                match_block["patterns_any"] = logic["patterns"]
            logic["match"] = match_block
        if "exclude" not in logic:
            logic["exclude"] = {}
        if "alert" not in logic:
            logic["alert"] = {}
        return logic

    def _match_conditions(self, content: str, match_logic: dict):
        matched = False
        reason = ""
        tokens = []
        severity = None

        if "patterns_any" in match_logic:
            for pattern in match_logic["patterns_any"]:
                all_found = True
                temp_tokens = []
                for part in pattern.get("all_of", []):
                    if "|" in part:
                        options = part.split("|")
                        found_opt = False
                        for opt in options:
                            opt_text = opt.strip()
                            if not opt_text: continue
                            
                            regex_parts = []
                            if opt_text[0].isalnum(): regex_parts.append(r'(?<!\w)')
                            regex_parts.append(re.escape(opt_text))
                            if opt_text[-1].isalnum(): regex_parts.append(r'(?!\w)')
                            
                            regex_str = "".join(regex_parts)
                            if re.search(regex_str, content, re.IGNORECASE):
                                found_opt = True
                                temp_tokens.append(opt_text)
                                break
                        if not found_opt:
                            all_found = False
                            break
                    else:
                        regex_parts = []
                        if part[0].isalnum(): regex_parts.append(r'(?<!\w)')
                        regex_parts.append(re.escape(part))
                        if part[-1].isalnum(): regex_parts.append(r'(?!\w)')
                        
                        regex_str = "".join(regex_parts)
                        if not re.search(regex_str, content, re.IGNORECASE):
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

        if not matched and "keywords_all" in match_logic:
            kws = match_logic["keywords_all"]
            if kws:
                all_found = True
                temp_tokens = []
                for kw in kws:
                    regex_parts = []
                    if kw[0].isalnum(): regex_parts.append(r'(?<!\w)')
                    regex_parts.append(re.escape(kw))
                    if kw[-1].isalnum(): regex_parts.append(r'(?!\w)')
                    regex_str = "".join(regex_parts)
                    if re.search(regex_str, content, re.IGNORECASE):
                        temp_tokens.append(kw)
                    else:
                        all_found = False
                        break
                if all_found:
                    matched = True
                    reason = "Keywords ALL match"
                    tokens = temp_tokens

        if not matched and "keywords_any" in match_logic:
            for kw in match_logic["keywords_any"]:
                regex_parts = []
                if kw[0].isalnum(): regex_parts.append(r'(?<!\w)')
                regex_parts.append(re.escape(kw))
                if kw[-1].isalnum(): regex_parts.append(r'(?!\w)')
                
                regex_str = "".join(regex_parts)
                if re.search(regex_str, content, re.IGNORECASE):
                    matched = True
                    reason = f"Keyword ANY match: {kw}"
                    tokens.append(kw)
                    break
                    
        return matched, reason, tokens, severity

    def _exclude_conditions(self, content: str, raw_log: dict, exclude_logic: dict):
        if not exclude_logic:
            return False, ""

        if "keywords_any" in exclude_logic:
            for kw in exclude_logic["keywords_any"]:
                if kw.lower() in content.lower():
                    return True, f"Exclude Keyword ANY: {kw}"

        if "keywords_all" in exclude_logic:
            kws = exclude_logic["keywords_all"]
            if kws and all(kw.lower() in content.lower() for kw in kws):
                return True, "Exclude Keywords ALL match"
                
        proc_path = raw_log.get("process_path", raw_log.get("exe", ""))
        if "process_paths_any" in exclude_logic and proc_path:
            for p in exclude_logic["process_paths_any"]:
                if p in proc_path:
                    return True, f"Exclude Process Path: {p}"
                    
        user = raw_log.get("user", raw_log.get("username", ""))
        if "users_any" in exclude_logic and user:
            if user in exclude_logic["users_any"]:
                return True, f"Exclude User: {user}"
                
        src_ip = raw_log.get("src_ip", raw_log.get("source_ip", ""))
        if "source_ips_any" in exclude_logic and src_ip:
            if src_ip in exclude_logic["source_ips_any"]:
                return True, f"Exclude Source IP: {src_ip}"
                
        dst_ip = raw_log.get("dst_ip", raw_log.get("destination_ip", ""))
        if "destination_ips_any" in exclude_logic and dst_ip:
            if dst_ip in exclude_logic["destination_ips_any"]:
                return True, f"Exclude Dest IP: {dst_ip}"
                
        if exclude_logic.get("destination_ips_private") and dst_ip:
            try:
                ip_obj = ipaddress.ip_address(dst_ip)
                if ip_obj.is_private or ip_obj.is_loopback:
                    return True, "Exclude Dest IP: Private/Loopback"
            except ValueError:
                pass

        return False, ""

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

        # 2. Content extraction
        content = raw_log.get("command_line") or raw_log.get("cmdline") or raw_log.get("message", "")
        if not content:
            return

        # 3. Global Exclusions (Whitelist)
        content_lower = content.lower()
        for exclusion in self.GLOBAL_EXCLUSIONS:
            if exclusion.lower() in content_lower:
                # print(f"[RuleEngine] Skipping excluded command: {content}")
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
