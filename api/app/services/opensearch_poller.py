import asyncio
import os
import json
from datetime import datetime, timedelta
import httpx
from .rule_engine import RuleEngine
from .. import db as database

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")

async def poll_opensearch_loop():
    print("Starting OpenSearch Rule Poller...", flush=True)
    last_run = datetime.utcnow() - timedelta(minutes=2)
    
    while True:
        try:
            now = datetime.utcnow()
            
            query = {
                "size": 1000,
                "query": {
                    "range": {
                        "@timestamp": {
                            "gt": last_run.isoformat() + "Z",
                            "lte": now.isoformat() + "Z"
                        }
                    }
                },
                "sort": [
                    {"@timestamp": {"order": "asc"}}
                ]
            }

            index_pattern = "siem-security-logs-*"
            
            async with httpx.AsyncClient() as client:
                # Check if index exists first (optional, but good practice, though search across * works too)
                res = await client.post(
                    f"{OPENSEARCH_URL}/{index_pattern}/_search", 
                    json=query
                )

                if res.status_code == 200:
                    response = res.json()
                    hits = response.get('hits', {}).get('hits', [])
                    if hits:
                        print(f"[Poller] Fetched {len(hits)} new logs from OpenSearch", flush=True)
                        db = database.SessionLocal()
                        try:
                            engine = RuleEngine(db)
                            for hit in hits:
                                source = hit['_source']
                                source['_id'] = hit['_id']
                                # Debug: Print what we are evaluating
                                cmd = source.get("command_line") or source.get("cmdline")
                                print(f"[Poller] Evaluating log {hit['_id']} (Host: {source.get('hostname')}, Cmd: {cmd})", flush=True)
                                engine.evaluate_raw(source)
                        finally:
                            db.close()
                elif res.status_code != 404:
                    print(f"[Poller] OpenSearch error: {res.text}", flush=True)

            last_run = now
        except httpx.ConnectError:
             print("[Poller] OpenSearch not reachable yet, retrying...", flush=True)
        except Exception as e:
            print(f"[Poller] Error: {e}", flush=True)
        
        # If we got a full batch, sleep less to catch up faster
        sleep_time = 1 if hits and len(hits) == 1000 else 5
        await asyncio.sleep(sleep_time)
