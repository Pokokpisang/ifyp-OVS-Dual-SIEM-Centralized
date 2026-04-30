import sys
import os
from sqlalchemy import create_engine, text

# Try localhost with user/password from docker-compose
db_url = "postgresql://user:password@localhost:5432/siemdb"

engine = create_engine(db_url)

with engine.connect() as conn:
    # Check if agent_id exists in alerts
    try:
        conn.execute(text("ALTER TABLE alerts ADD COLUMN agent_id VARCHAR;"))
        print("[+] Added agent_id to alerts")
    except Exception as e:
        print(f"[-] Alerts agent_id: {e}")

    # Check if agent_id exists in logs
    try:
        conn.execute(text("ALTER TABLE logs ADD COLUMN agent_id VARCHAR;"))
        print("[+] Added agent_id to logs")
    except Exception as e:
        print(f"[-] Logs agent_id: {e}")

    conn.commit()
