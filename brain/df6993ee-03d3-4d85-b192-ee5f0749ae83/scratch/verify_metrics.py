import httpx
import time
import json
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# API Config
API_URL = "http://localhost:8000"
AGENT_KEY = "OSnyTU2uR13nNO67srAI_RXNZ4Ywt1mcpeBftPqAyrk"
AGENT_ID = "9567eec2-decf-4c7c-8fed-e647bec4392c"

# Send high CPU metric
metric_payload = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "host": "verify-host",
    "cpu_percent": 99.0,
    "ram_percent": 50.0,
    "net_in_bytes": 1000,
    "net_out_bytes": 2000
}

print(f"[*] Sending high CPU metric...")
resp = httpx.post(f"{API_URL}/api/metrics", json=metric_payload, headers={"X-Agent-Key": AGENT_KEY})
print(f"Response: {resp.status_code} - {resp.json()}")

# Wait for processing
print("[*] Waiting for processing...")
time.sleep(2)

# Check Alerts in DB
sys.path.append("/home/pokokpisang/Desktop/FYP/ifyp/prototype/agent/api")
from app import models
db_url = "postgresql://user:password@localhost:5432/siemdb"
engine = create_engine(db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

print("\n--- RECENT METRIC ALERTS ---")
metric_alert = db.query(models.Alert).filter(models.Alert.detection_engine == "MetricEngine").order_by(models.Alert.timestamp.desc()).first()
if metric_alert:
    print(f"ID: {metric_alert.id} | Title: {metric_alert.title} | Host: {metric_alert.host} | AgentID: {metric_alert.agent_id}")
    if metric_alert.agent_id == AGENT_ID:
        print(f"[+] SUCCESS: Metric Alert correctly associated with Agent ID {AGENT_ID}")
    else:
        print(f"[-] ERROR: Metric Alert Agent ID mismatch. Expected {AGENT_ID}, got {metric_alert.agent_id}")
else:
    print("[-] FAILURE: Metric alert not found.")

db.close()
