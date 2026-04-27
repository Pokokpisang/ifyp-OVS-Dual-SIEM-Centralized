import json
import httpx
import asyncio
import os
import sys
sys.path.append('/app')
from datetime import datetime, timedelta
from app import db
from app import models

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")

async def backfill():
    session = db.SessionLocal()
    alerts = session.query(models.Alert).filter(~models.Alert.description.like("%RAW_LOG:%")).all()
    print(f"Found {len(alerts)} alerts to backfill")
    
    async with httpx.AsyncClient() as client:
        for alert in alerts:
            start = alert.timestamp - timedelta(seconds=2)
            end = alert.timestamp + timedelta(seconds=2)
            
            query = {
                "size": 50,
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"hostname": alert.host}},
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start.isoformat() + "Z",
                                        "lte": end.isoformat() + "Z"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
            
            try:
                res = await client.post(f"{OPENSEARCH_URL}/_search", json=query)
                if res.status_code == 200:
                    hits = res.json().get('hits', {}).get('hits', [])
                    raw_msg = None
                    for hit in hits:
                        source = hit['_source']
                        msg = source.get('message', '')
                        if "Command:" in alert.description:
                            parts = alert.description.split("Command: ")
                            if len(parts) > 1:
                                cmd_part = parts[1].strip()
                                if cmd_part and cmd_part in msg:
                                    raw_msg = msg
                                    break
                    
                    if not raw_msg and hits:
                        raw_msg = hits[0]['_source'].get('message', '')
                        
                    if raw_msg:
                        alert.description = f"{alert.description}\n\nRAW_LOG: {raw_msg}"
                        session.commit()
            except Exception as e:
                pass
                
    session.close()
    print("Backfill complete.")

if __name__ == "__main__":
    asyncio.run(backfill())
