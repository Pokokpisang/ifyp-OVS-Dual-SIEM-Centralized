import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from api.app import models

# Get DB URL from api/app/db.py or just use the sqlite/postgres default
from api.app.db import engine, SessionLocal

db = SessionLocal()

rule = db.query(models.DetectionRule).filter(models.DetectionRule.id == 1).first()
if rule:
    logic = {
        "match": {
            "keywords_any": ["base64", "nc", "bash -i", "sh -c", "chmod +x"],
            "patterns_any": [
                {"name": "download_pipe_shell", "all_of": ["curl|wget", "| sh| | bash"], "severity": "HIGH"},
                {"name": "suspicious_downloader_sh", "all_of": ["curl|wget", ".sh"], "severity": "HIGH"},
                {"name": "suspicious_downloader_out", "all_of": ["curl|wget", "http", "-o|-O|--output"], "severity": "MED"},
                {"name": "base64_decode_exec", "all_of": ["base64", "bash|sh|python"], "severity": "HIGH"},
                {"name": "netcat_shell", "all_of": ["nc", "-e|bash -i|python -c"], "severity": "HIGH"}
            ]
        },
        "exclude": {
            "keywords_any": [
                "localhost", 
                "127.0.0.1", 
                "/api/agent/rules", 
                "/api/ingest", 
                "healthcheck", 
                "pg_isready", 
                "antigravity", 
                "cpuUsage.sh", 
                "/usr/share/antigravity/"
            ]
        },
        "alert": {
            "message": "Suspicious command execution detected.",
            "severity": "MED"
        }
    }
    rule.logic_json = json.dumps(logic)
    rule.rule_type = "server"
    db.commit()
    print("Rule 1 updated.")
else:
    print("Rule 1 not found.")
db.close()
