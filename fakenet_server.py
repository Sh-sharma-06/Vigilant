import asyncio
import logging
import os
from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
import uvicorn

class ProtocolEnum(str, Enum):
    HTTP = "HTTP"
    DNS = "DNS"

class NetworkEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    protocol: ProtocolEnum
    client_ip: str
    target_host: str
    request_path: Optional[str] = None
    method: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    payload_preview: Optional[str] = None

LOG_FILE = "/logs/network_telemetry.json"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FakeNet")

def log_event(event: NetworkEvent):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(event.model_dump_json() + "\n")
    except Exception as e:
        logger.error(f"Failed to log telemetry: {e}")

app = FastAPI(title="Vigilant FakeNet Sinkhole")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def catch_all(request: Request, path: str):
    body = await request.body()
    query_str = f"?{request.url.query}" if request.url.query else ""
    log_event(NetworkEvent(
        protocol=ProtocolEnum.HTTP,
        client_ip=request.client.host if request.client else "unknown",
        target_host=request.headers.get("host", "unknown"),
        request_path=f"/{path}{query_str}",
        method=request.method,
        headers=dict(request.headers),
        payload_preview=body[:500].decode(errors="replace") if body else None
    ))
    return {"status": "ok", "sinkhole": "vigilant-fakenet"}

class DNSSinkhole(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            qname = str(request.q.qname).rstrip('.')
            qtype = request.q.qtype

            # Return 172.20.0.2 for IPv4 (A); return empty NOERROR for IPv6 (AAAA) so glibc uses IPv4 in 1ms!
            if qtype == QTYPE.A:
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("172.20.0.2"), ttl=60))
                log_event(NetworkEvent(protocol=ProtocolEnum.DNS, client_ip=addr[0], target_host=qname))

            self.transport.sendto(reply.pack(), addr)
        except Exception as e:
            logger.error(f"DNS error: {e}")

async def main():
    os.makedirs("/logs", exist_ok=True)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: DNSSinkhole(), local_addr=('0.0.0.0', 53))
    config = uvicorn.Config(app=app, host="0.0.0.0", port=80, loop="asyncio")
    server = uvicorn.Server(config)
    try:
        await server.serve()
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())
