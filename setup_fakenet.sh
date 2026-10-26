#!/bin/bash
set -e

echo "[*] Creating air-gapped Vigilant network..."
# The --internal flag strictly forbids outbound internet access, creating a perfect air-gap
sudo docker network create \
    --driver bridge \
    --internal \
    --subnet 172.20.0.0/16 \
    vigilant-net || echo "[!] Network already exists"

echo "[*] Building FakeNet Dockerfile..."
cat << 'EOF' > Dockerfile.fakenet
FROM python:3.10-slim
WORKDIR /app
RUN pip install fastapi uvicorn pydantic
COPY fakenet_server.py /app/
CMD ["python", "fakenet_server.py"]
EOF

sudo docker build -t vigilant-fakenet -f Dockerfile.fakenet .

echo "[*] Launching FakeNet Sinkhole..."
# Bind it to a static IP so we can route the sandbox DNS directly to it
sudo docker run -d \
    --name fakenet_server \
    --network vigilant-net \
    --ip 172.20.0.2 \
    -v $(pwd)/logs:/logs \
    --rm \
    vigilant-fakenet

echo "[+] FakeNet is active and listening on 172.20.0.2"
