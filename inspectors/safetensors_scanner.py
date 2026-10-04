"""
Vigilant Safetensors Inspector
==============================
Static scanner for the Safetensors format. Fully dependency-free.

Checks:
  * 8-byte little-endian header length sanity (anti DoS / allocation bomb)
  * polyglot markers in the raw byte stream (ELF / PE / shell / ZIP)
  * JSON metadata: path-traversal keys, embedded scripts, base64 blobs
  * tensor data_offsets strictly inside the declared buffer region
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import struct
from typing import Any, Dict, List

MAX_HEADER_SIZE = 100 * 1024 * 1024          # 100 MiB of JSON is already absurd
FORMAT = "SAFETENSORS"

POLYGLOT_MARKERS = {
    b"\x7fELF": "ELF executable",
    b"MZ": "PE/DOS executable",
    b"#!/bin/": "shell script shebang",
    b"PK\x03\x04": "ZIP archive",
}
TRAVERSAL_PATTERNS = ("../", "..\\", "/etc/", "\\etc\\", "~/.")
SCRIPT_PATTERNS = ("__import__", "os.system", "subprocess", "eval(", "exec(",
                   "import os", "import sys", "base64.b64decode", "/bin/sh",
                   "/bin/bash", "powershell")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def _report(model_name: str, verdict: str, confidence: str, attack_vector: str,
            summary: str, **details: Any) -> Dict[str, Any]:
    return {
        "model_name": model_name,
        "format": FORMAT,
        "verdict": verdict,
        "confidence": confidence,
        "attack_vector": attack_vector,
        "summary": summary,
        "technical_details": details,
    }


def _looks_like_b64_blob(value: str) -> str:
    """Return a description if *value* decodes to something executable."""
    candidate = value.strip().replace("\\n", "")
    if len(candidate) < 64 or not _B64_RE.match(candidate):
        return ""
    try:
        raw = base64.b64decode(candidate, validate=False)
    except (binascii.Error, ValueError):
        return ""
    for magic, desc in ((b"\x7fELF", "ELF binary"), (b"MZ", "PE binary"),
                        (b"PK\x03\x04", "ZIP archive"),
                        (b"#!/bin/", "shell script")):
        if raw.startswith(magic):
            return f"base64-encoded {desc}"
    for needle in SCRIPT_PATTERNS:
        if needle.encode() in raw[:4096]:
            return f"base64 blob containing '{needle}'"
    return ""


def scan_safetensors(path: str) -> Dict[str, Any]:
    """Statically inspect a .safetensors file. Returns Vigilant telemetry."""
    name = os.path.basename(path)
    findings: List[str] = []
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return _report(name, "SUSPICIOUS", "LOW", "NONE",
                       f"Unreadable file: {exc}", error=str(exc))

    file_size = len(data)
    if file_size < 8:
        return _report(name, "SUSPICIOUS", "MEDIUM", "NONE",
                       "Truncated file: smaller than the 8-byte length prefix.",
                       file_size=file_size)

    # ---- 1. header length sanity ------------------------------------- #
    (header_size,) = struct.unpack("<Q", data[:8])
    if header_size == 0 or header_size > MAX_HEADER_SIZE or 8 + header_size > file_size:
        return _report(name, "MALICIOUS", "HIGH", "DOS_BOMB",
                       f"Invalid JSON header size {header_size} (file is "
                       f"{file_size} bytes) — DoS / allocation-bomb pattern.",
                       header_size=header_size, file_size=file_size)

    header_raw = data[8:8 + header_size]
    buffer_size = file_size - 8 - header_size

    # ---- 2. polyglot markers ------------------------------------------ #
    polyglot_hits = []
    scan_regions = (("file-prefix", data[:8]),
                    ("header", header_raw),
                    ("tensor-buffer", data[8 + header_size:]))
    for region, blob in scan_regions:
        for magic, desc in POLYGLOT_MARKERS.items():
            idx = blob.find(magic)
            if idx != -1:
                polyglot_hits.append(f"{desc} marker in {region} @+{idx}")
    if polyglot_hits:
        findings.extend(polyglot_hits)

    # ---- 3. JSON header parsing --------------------------------------- #
    try:
        header: Dict[str, Any] = json.loads(header_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _report(name, "SUSPICIOUS", "MEDIUM", "NONE",
                       f"Header is not valid UTF-8 JSON: {exc}",
                       header_size=header_size, file_size=file_size,
                       polyglot=polyglot_hits)

    meta = header.get("__metadata__", {}) or {}
    traversal_hits, script_hits = [], []

    for key in list(header.keys()) + list(meta.keys()):
        lowered = str(key).lower()
        if any(p in lowered for p in TRAVERSAL_PATTERNS) or lowered.startswith("/"):
            traversal_hits.append(str(key))
    for mkey, mval in meta.items():
        if not isinstance(mval, str):
            continue
        for needle in SCRIPT_PATTERNS:
            if needle in mval:
                script_hits.append(f"metadata[{mkey}] contains '{needle}'")
        blob_desc = _looks_like_b64_blob(mval)
        if blob_desc:
            script_hits.append(f"metadata[{mkey}] holds {blob_desc}")

    # ---- 4. tensor offset bounds -------------------------------------- #
    offset_violations = []
    tensors = {k: v for k, v in header.items() if k != "__metadata__"}
    for tname, tinfo in tensors.items():
        offsets = (tinfo or {}).get("data_offsets")
        if not (isinstance(offsets, list) and len(offsets) == 2):
            offset_violations.append(f"{tname}: missing/invalid data_offsets")
            continue
        begin, end = offsets
        if begin < 0 or end < begin or end > buffer_size:
            offset_violations.append(
                f"{tname}: data_offsets {offsets} outside buffer "
                f"[0, {buffer_size}]")

    # ---- verdict ------------------------------------------------------- #
    details = dict(header_size=header_size, file_size=file_size,
                   tensor_count=len(tensors), metadata_keys=list(meta.keys()),
                   polyglot=polyglot_hits, traversal_keys=traversal_hits,
                   script_indicators=script_hits,
                   offset_violations=offset_violations)

    if offset_violations:
        return _report(name, "MALICIOUS", "HIGH", "DOS_BOMB",
                       "Tensor data_offsets escape the declared buffer — "
                       "out-of-bounds read / crash primitive.", **details)
    if polyglot_hits:
        return _report(name, "MALICIOUS", "HIGH", "POLYGLOT",
                       "Executable/archive markers embedded in the "
                       "safetensors byte stream (polyglot file).", **details)
    if traversal_hits:
        return _report(name, "MALICIOUS", "HIGH", "PATH_TRAVERSAL",
                       "Header keys contain path-traversal sequences.", **details)
    if script_hits:
        return _report(name, "SUSPICIOUS", "MEDIUM", "POLYGLOT",
                       "Suspicious executable content in string metadata.",
                       **details)
    return _report(name, "BENIGN", "HIGH", "NONE",
                   f"Clean safetensors: {len(tensors)} tensors, "
                   f"offsets in bounds, no polyglot markers.", **details)


if __name__ == "__main__":
    import sys
    print(json.dumps(scan_safetensors(sys.argv[1]), indent=2))
