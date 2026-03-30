.PHONY: up down restart logs build-agent

up: build-agent
	@echo "🚀 Starting backend services (API & DB)..."
	docker-compose up -d --build
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
	@echo "➡️  Dashboard:  http://localhost:8000/dashboard"
	@echo "➡️  Agent Logs: tail -f agent.log"
	@echo "➡️  Services:   docker-compose logs -f"
	@echo ""
	@echo "🛑 To stop everything, run: make down"

build-agent:
	@echo "🔨 Building Go Agent..."
	@cd agent && go build -o agent ./cmd/agent/main.go
	@echo "✅ Agent built successfully."

down:
	@echo "🛑 Stopping Backend services..."
	docker-compose down
	@echo "🛑 Stopping Go Agent..."
	@-sudo pkill -f "./agent/agent" 2>/dev/null || true
	@echo "✅ Everything stopped."

restart: down up

logs:
	docker-compose logs -f
