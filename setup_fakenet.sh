#!/bin/bash
set -e

echo "[*] Creating isolated internal network (no real internet access)..."
docker network create --internal fakenet-isolated 2>/dev/null || echo "    (network already exists, continuing)"

echo "[*] Building fakenet sinkhole image..."
docker build -f Dockerfile.fakenet -t fakenet-sinkhole .

echo "[*] Starting sinkhole container on the isolated network..."
docker rm -f fakenet-sinkhole-container 2>/dev/null || true
docker run -d \
    --name fakenet-sinkhole-container \
    --network fakenet-isolated \
    -v "$(pwd)/fakenet_logs:/sandbox/fakenet_logs" \
    fakenet-sinkhole

echo "[+] Sinkhole is up. Logs will appear in ./fakenet_logs/fakenet_log.jsonl"
docker ps --filter "name=fakenet-sinkhole-container"