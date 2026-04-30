import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add api to path
sys.path.append("/home/pokokpisang/Desktop/FYP/ifyp/prototype/agent/api")
from app import models

# Use docker credentials as they worked for migration
db_url = "postgresql://user:password@localhost:5432/siemdb"
engine = create_engine(db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

# We can't see the raw key, so we'll create a new agent and get its key
from app.services.agent_service import create_agent, register_agent

# 1. Create a test agent
agent, token = create_agent(
    agent_name="VerificationAgent",
    group="Test",
    tags="test,verify",
    os_type="Linux",
    distribution="Ubuntu 22.04",
    architecture="x86_64",
    enable_logs=True,
    enable_fim=False,
    enable_metrics=True,
    db=db
)

print(f"Token: {token}")

# 2. Register it to get the raw key
key = register_agent(
    token=token,
    hostname="verify-host",
    ip_address="1.2.3.4",
    os="linux",
    arch="amd64",
    db=db
)

print(f"Agent Key: {key}")
print(f"Agent ID: {agent.agent_id}")

db.close()
