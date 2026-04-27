import json
from app import models
from app.db import SessionLocal

db = SessionLocal()
rules = db.query(models.DetectionRule).all()
for r in rules:
    print(f"Rule ID: {r.id}, Name: {r.name}, Type: {r.rule_type}")
    print(r.logic_json)
    print("---")
db.close()
