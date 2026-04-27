import json
from app import models
from app.db import SessionLocal

db = SessionLocal()
alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(10).all()
for a in alerts:
    print(f"Alert ID: {a.id}, Title: {a.title}")
    print(f"Desc: {a.description}")
    print("---")
db.close()
