# SIEM Prototype (50% MVP)

This is a prototype SIEM system consisting of:
1.  **Backend**: FastAPI (Python) + PostgreSQL (Dockerized).
2.  **Agent**: Go-based endpoint agent that tails logs and sends them to the backend.
3.  **Dashboard**: Web-interface for monitoring and searching logs.

## Prerequisites
- Docker & Docker Compose
- Go 1.18+ (Development only, if building agent from source)
- Linux environment (for log paths)

## Quick Start

The easiest way to start the entire system (backend + agent) is using the provided `Makefile`.

### Start Everything
```bash
make up
```
*Note: You may be prompted for your sudo password, as the agent requires root privileges to read system logs like `/var/log/syslog`.*

Access the Dashboard: **http://localhost:8000/dashboard**

### Stop Everything
```bash
make down
```

### Manual Setup (Without Makefile)

### 1. Start the Backend

### 2. Run the Agent
The agent runs natively on the host to access logs and system metrics.

Build the agent (if not already built):
```bash
cd agent
go build -o agent ./cmd/agent/main.go
cd ..

sudo AGENT_LOG_PATH=/var/log/syslog \
     AGENT_LOG_TYPE=syslog \
     AGENT_AUDITD_PATH=/var/log/audit/audit.log \
     ./agent
```

### 3. Run with Real Data (Syslog/Auth.log)
To monitor real system logs like `/var/log/syslog` or `/var/log/auth.log`, you generally need **root** permissions.

```bash
# Monitor System Logs (General activity)
sudo AGENT_LOG_PATH=/var/log/syslog AGENT_LOG_TYPE=syslog ./agent/agent/agent

# OR Monitor Auth Logs (Login attempts)
sudo AGENT_LOG_PATH=/var/log/auth.log AGENT_LOG_TYPE=auth ./agent/agent/agent
```
*Note: Make sure your `AGENT_SERVER_URL` is set if it's not the default (localhost:8000).*

### 4. Verify
Trigger a log event manually to test:
```bash
# This writes a test message to /var/log/syslog
logger "SIEM Test: Hello from the real world"
```

Check the UI:
- **Dashboard**: http://localhost:8000/dashboard
- **Logs**: http://localhost:8000/logs

## Features
- **Log Ingestion**: Tails files in real-time.
- **Metrics**: Collects CPU, RAM, and Network stats every 5s.
- **Alerting**: Simple rule checks (e.g., High CPU) on ingestion.
- **Visualization**: Chart.js graphs and live KPI cards.
