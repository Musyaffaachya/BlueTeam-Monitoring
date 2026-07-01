#!/bin/bash
# ============================================================
#  Blueteam Agent Deploy Script - Linux
#  Jalankan di mesin TARGET yang ingin dimonitor
#
#  Usage:
#    chmod +x deploy-agent-linux.sh
#    sudo ./deploy-agent-linux.sh <CENTRAL_SERVER_IP>
# ============================================================

set -e

CENTRAL_IP="${1}"

if [ -z "$CENTRAL_IP" ]; then
    echo "Usage: sudo ./deploy-agent-linux.sh <CENTRAL_SERVER_IP>"
    echo "Contoh: sudo ./deploy-agent-linux.sh 192.168.1.100"
    exit 1
fi

echo "[*] Deploying Blueteam Agent → Central: $CENTRAL_IP"

# Ganti placeholder IP di config
sed "s/CENTRAL_SERVER_IP/$CENTRAL_IP/g" fluent-bit/agent-linux.conf > /tmp/agent-fluent-bit.conf

# Jalankan Fluent Bit sebagai container
docker run -d \
    --name blueteam-agent \
    --restart unless-stopped \
    --hostname "$(hostname)" \
    -v /tmp/agent-fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro \
    -v /var/log:/var/log:ro \
    -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
    fluent/fluent-bit:3.1

echo "[OK] Agent berjalan. Cek dengan: docker logs blueteam-agent"
echo "[OK] Log dikirim ke $CENTRAL_IP:5170"
