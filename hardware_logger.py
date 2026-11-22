"""Send a compact Vigilant audit record to the ESP32 over USB serial.

Enabled only when VIGILANT_ESP32_PORT is set (e.g. COM3 or /dev/ttyUSB0),
so the pipeline still runs normally on machines without the hardware.
"""

import hashlib
import json
import os
import time
from pathlib import Path

try:
    import serial  # pip install pyserial
except ImportError:
    serial = None

BAUD = 115200


def _open(port: str, baud: int):
    """Open the port WITHOUT toggling DTR/RTS, so the board is not reset
    (or dropped into bootloader mode) every time we connect."""
    ser = serial.Serial()
    ser.port, ser.baudrate, ser.timeout = port, baud, 3
    ser.dtr = False
    ser.rts = False
    ser.open()
    time.sleep(0.5)
    ser.reset_input_buffer()
    return ser


def build_record(report: dict) -> dict:
    """Small summary line + SHA-256 of the full report (keeps flash usage low)."""
    full = json.dumps(report, sort_keys=True, default=str).encode("utf-8")
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": Path(str(report.get("model", ""))).name,
        "verdict": report.get("verdict"),
        "static": (report.get("static") or {}).get("verdict"),
        "triage": (report.get("triage") or {}).get("verdict"),
        "report_sha256": hashlib.sha256(full).hexdigest(),
    }


def log_to_esp32(report: dict, port: str | None = None, baud: int = BAUD) -> bool:
    """Returns True only if the ESP32 acknowledged the write. Never raises."""
    port = port or os.environ.get("VIGILANT_ESP32_PORT")
    if not port:
        return False  # hardware logging not configured
    if serial is None:
        print("[Hardware Log] pyserial not installed (pip install pyserial)")
        return False

    line = json.dumps(build_record(report), default=str, separators=(",", ":"))
    try:
        with _open(port, baud) as ser:
            ser.write((line + "\n").encode("utf-8"))
            ser.flush()
            for _ in range(5):          # skip any stray lines until we see a reply
                reply = ser.readline().decode("utf-8", errors="replace").strip()
                if reply.startswith("ACK"):
                    print(f"[Hardware Log] {reply}")
                    return True
                if reply.startswith("ERR"):
                    print(f"[Hardware Log Error] {reply}")
                    return False
            print("[Hardware Log Error] no acknowledgment from ESP32")
            return False
    except Exception as e:  # serial.SerialException, permission errors, etc.
        print(f"[Hardware Log Error] {e}")
        return False


def dump_esp32_logs(port: str | None = None, baud: int = BAUD) -> list[str]:
    """Read back every stored record (for audits / the demo)."""
    port = port or os.environ.get("VIGILANT_ESP32_PORT")
    lines, capturing = [], False
    with _open(port, baud) as ser:
        ser.write(b"DUMP\n")
        while True:
            raw = ser.readline().decode("utf-8", errors="replace").strip()
            if not raw and not capturing:
                break
            if raw == "---BEGIN LOG---":
                capturing = True
            elif raw == "---END LOG---":
                break
            elif capturing and raw:
                lines.append(raw)
    return lines


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "dump":
        for entry in dump_esp32_logs():
            print(entry)
    else:  # quick smoke test
        ok = log_to_esp32({"model": "smoke_test.pt", "verdict": "TEST"})
        print("acknowledged" if ok else "failed")