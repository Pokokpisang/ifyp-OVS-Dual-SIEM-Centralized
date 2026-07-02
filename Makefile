.PHONY: up down restart logs build-agent fix-perms

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
