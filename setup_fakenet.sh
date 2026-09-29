#!/bin/bash
set -euo pipefail

echo "1. Creating isolated internal Docker network..."
docker network create --internal fakenet-isolated 2>/dev/null || true

echo "2. Building and starting the sinkhole container..."
docker build -t vigilant-fakenet -f Dockerfile.fakenet .
docker rm -f fakenet-sinkhole 2>/dev/null || true
docker run -d \
    --name fakenet-sinkhole \
    --network fakenet-isolated \
    -v "$(pwd)/fakenet_logs:/sandbox/fakenet_logs" \
    vigilant-fakenet

echo "3. Routing bridge traffic to sinkhole..."
SINKHOLE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' fakenet-sinkhole)
NETWORK_ID=$(docker network inspect fakenet-isolated -f '{{.Id}}' | cut -c 1-12)
BRIDGE_IF="br-$NETWORK_ID"

# fakenet_server listens on 8080. Do not duplicate the host-level rule when
# setup is run repeatedly; this requires Docker on a Linux host and sudo.
RULE=(-t nat -A PREROUTING -i "$BRIDGE_IF" ! -d "$SINKHOLE_IP" -p tcp -j DNAT --to-destination "$SINKHOLE_IP:8080")
CHECK_RULE=(-t nat -C PREROUTING -i "$BRIDGE_IF" ! -d "$SINKHOLE_IP" -p tcp -j DNAT --to-destination "$SINKHOLE_IP:8080")
if ! sudo iptables "${CHECK_RULE[@]}" 2>/dev/null; then
    sudo iptables "${RULE[@]}"
fi

echo "Fake network is live. Sinkhole IP: $SINKHOLE_IP"
