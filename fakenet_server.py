"""
Minimal fake-internet sinkhole for the ml-sandbox.

Accepts any incoming TCP connection, logs the source and a preview of
whatever was sent, and replies with a small well-formed response so a
program checking its own exit code (e.g. curl) doesn't notice anything
unusual -- this is what lets us observe a model's outbound *attempt*
without ever letting it reach the real internet.
"""
import socket
import threading
import json
import datetime
import os

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
LOG_PATH = "/sandbox/fakenet_logs/fakenet_log.jsonl"


def log_connection(addr, data_preview):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source_ip": addr[0],
        "source_port": addr[1],
        "data_preview": data_preview,
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[fakenet] Logged connection from {addr[0]}:{addr[1]}")


def handle_client(conn, addr):
    try:
        conn.settimeout(2)
        try:
            data = conn.recv(1024)
            preview = data.decode(errors="replace")[:200]
        except socket.timeout:
            preview = "(no data received before timeout)"

        log_connection(addr, preview)

        # Generic, well-formed response so the caller's own error handling
        # doesn't trip a sandbox-detection heuristic on the malware's side.
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"OK"
        )
        conn.sendall(response)
    except Exception as e:
        print(f"[fakenet] Error handling {addr}: {e}")
    finally:
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(20)
    print(f"[fakenet] Sinkhole listening on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()