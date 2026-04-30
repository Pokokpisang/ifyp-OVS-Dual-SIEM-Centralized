import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add api to path
sys.path.append("/home/pokokpisang/Desktop/FYP/ifyp/prototype/agent/api")
from app import models

engine = create_engine("sqlite:////home/pokokpisang/Desktop/FYP/ifyp/prototype/agent/api/siem.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

agents = db.query(models.AgentRecord).all()
for a in agents:
    print(f"ID: {a.agent_id} | Name: {a.agent_name} | Status: {a.status} | KeyHash: {a.agent_key_hash}")

db.close()
