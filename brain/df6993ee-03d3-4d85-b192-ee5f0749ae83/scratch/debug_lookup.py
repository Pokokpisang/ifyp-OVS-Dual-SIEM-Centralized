import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add api to path
sys.path.append("/home/pokokpisang/Desktop/FYP/ifyp/prototype/agent/api")
from app import models
from app.services.agent_service import get_agent_metadata_by_key, _sha256

# Use docker credentials
db_url = "postgresql://user:password@localhost:5432/siemdb"
engine = create_engine(db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

key = "OSnyTU2uR13nNO67srAI_RXNZ4Ywt1mcpeBftPqAyrk"
meta = get_agent_metadata_by_key(key, db)
print(f"Meta: {meta}")

if not meta:
    print(f"Key Hash: {_sha256(key)}")
    agent = db.query(models.AgentRecord).filter(models.AgentRecord.agent_key_hash == _sha256(key)).first()
    if agent:
        print(f"Found agent with ID: {agent.agent_id}")
    else:
        print("Agent not found in DB with this key hash.")
        # List some hashes
        agents = db.query(models.AgentRecord).limit(5).all()
        for a in agents:
            print(f"Agent {a.agent_id} Hash: {a.agent_key_hash}")

db.close()
