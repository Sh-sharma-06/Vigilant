"""
Pure-Python Protobuf Wire-Format ONNX Security Scanner (Zero External Dependencies).
Walks ModelProto -> GraphProto -> NodeProto / TensorProto without loading tensor weights.
Detects:
  1. External data path traversal (arbitrary file read via TensorProto.external_data)
  2. Hostile custom operators & non-standard execution domains (PyFunc, PythonOp)
  3. Malformed / deeply nested Protobuf DoS payloads
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Tuple

HOSTILE_OPS = {
    "pyfunc", "pythonop", "eagerpyfunc", "pyfuncstateless",
    "exec", "eval", "system", "shell", "popen", "custompython",
}
STANDARD_DOMAINS = {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training", "com.microsoft"}
MAX_DEPTH = 32


def _read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    n = len(buf)
    while pos < n:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("Varint overflow")
    raise ValueError("Truncated varint")


def _iter_fields(buf: bytes):
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            val, pos = _read_varint(buf, pos)
            yield field_num, wire_type, val
        elif wire_type == 1:
            if pos + 8 > n:
                raise ValueError("Truncated 64-bit field")
            yield field_num, wire_type, buf[pos:pos + 8]
            pos += 8
        elif wire_type == 2:
            length, pos = _read_varint(buf, pos)
            if pos + length > n:
                raise ValueError("Truncated length-delimited field")
            yield field_num, wire_type, buf[pos:pos + length]
            pos += length
        elif wire_type == 5:
            if pos + 4 > n:
                raise ValueError("Truncated 32-bit field")
            yield field_num, wire_type, buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")


def _check_external_data(kv_bytes: bytes, findings: List[Dict[str, Any]]) -> None:
    key, val = "", ""
    for fnum, wtype, data in _iter_fields(kv_bytes):
        if wtype == 2:
            text = data.decode("utf-8", errors="replace")
            if fnum == 1:
                key = text
            elif fnum == 2:
                val = text
    if key.lower() == "location":
        if ".." in val or val.startswith("/") or val.startswith("\\") or (len(val) > 1 and val[1] == ":"):
            findings.append({
                "severity": "MALICIOUS",
                "type": "ONNX_PATH_TRAVERSAL",
                "detail": f"External tensor location escapes model directory: {val!r}",
            })


def _parse_tensor(tensor_bytes: bytes, findings: List[Dict[str, Any]]) -> None:
    for fnum, wtype, data in _iter_fields(tensor_bytes):
        # Field 13 = repeated StringStringEntryProto external_data
        if fnum == 13 and wtype == 2:
            _check_external_data(data, findings)


def _parse_node(node_bytes: bytes, findings: List[Dict[str, Any]], ops_seen: set, domains_seen: set) -> None:
    op_type, domain, name = "", "", ""
    for fnum, wtype, data in _iter_fields(node_bytes):
        if wtype == 2:
            if fnum == 3:
                name = data.decode("utf-8", errors="replace")
            elif fnum == 4:
                op_type = data.decode("utf-8", errors="replace")
            elif fnum == 7:
                domain = data.decode("utf-8", errors="replace")
    if op_type:
        ops_seen.add(op_type)
        if op_type.lower() in HOSTILE_OPS:
            findings.append({
                "severity": "MALICIOUS",
                "type": "ONNX_HOSTILE_OP",
                "detail": f"Hostile operator {op_type!r} in node {name!r} (domain={domain!r})",
            })
    if domain:
        domains_seen.add(domain)
        if domain not in STANDARD_DOMAINS:
            findings.append({
                "severity": "SUSPICIOUS",
                "type": "ONNX_CUSTOM_DOMAIN",
                "detail": f"Non-standard operator domain {domain!r} on op {op_type!r}",
            })


def _parse_graph(graph_bytes: bytes, findings: List[Dict[str, Any]], ops_seen: set, domains_seen: set, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        findings.append({"severity": "MALICIOUS", "type": "ONNX_PROTOBUF_DOS", "detail": "Excessive graph nesting depth"})
        return
    for fnum, wtype, data in _iter_fields(graph_bytes):
        if wtype != 2:
            continue
        if fnum == 1:  # repeated NodeProto node
            _parse_node(data, findings, ops_seen, domains_seen)
        elif fnum == 5:  # repeated TensorProto initializer
            _parse_tensor(data, findings)


def scan_onnx(path: str) -> Dict[str, Any]:
    p = Path(path)
    findings: List[Dict[str, Any]] = []
    ops_seen: set = set()
    domains_seen: set = set()
    ir_version = None

    try:
        raw = p.read_bytes()
        for fnum, wtype, data in _iter_fields(raw):
            if fnum == 1 and wtype == 0:
                ir_version = int(data)
            elif fnum == 7 and wtype == 2:  # GraphProto graph
                _parse_graph(data, findings, ops_seen, domains_seen)
    except Exception as e:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.60,
            "format": "ONNX",
            "summary": f"Malformed ONNX Protobuf structure: {e}",
            "findings": [{"severity": "SUSPICIOUS", "type": "ONNX_PARSE_ERROR", "detail": str(e)}],
            "features": {"format": "ONNX", "parse_error": str(e)},
        }

    has_mal = any(f["severity"] == "MALICIOUS" for f in findings)
    has_susp = any(f["severity"] == "SUSPICIOUS" for f in findings)

    if has_mal:
        verdict, conf = "MALICIOUS", 0.96
        summary = f"Hostile ONNX construct detected ({findings[0]['type']}): {findings[0]['detail']}"
    elif has_susp:
        verdict, conf = "SUSPICIOUS", 0.72
        summary = f"Custom ONNX domain requires review: {findings[0]['detail']}"
    else:
        verdict, conf = "BENIGN", 0.95
        summary = f"Clean ONNX Protobuf graph (ir_version={ir_version}, ops={len(ops_seen)})"

    return {
        "verdict": verdict,
        "confidence": conf,
        "format": "ONNX",
        "summary": summary,
        "findings": findings,
        "features": {
            "format": "ONNX",
            "ir_version": ir_version,
            "op_count": len(ops_seen),
            "ops_sample": sorted(ops_seen)[:25],
            "domains": sorted(domains_seen),
        },
    }

scan = scan_onnx
inspect_onnx = scan_onnx
