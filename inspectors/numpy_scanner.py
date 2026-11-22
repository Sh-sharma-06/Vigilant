"""
Pure-Python NumPy (.npy) Security Scanner.
Reads the binary .npy header without executing numpy.load(allow_pickle=True).
  - Numeric dtypes -> BENIGN
  - Object dtype ('O') -> inspects embedded Pickle stream via pickletools.genops
"""
from __future__ import annotations
import ast
import io
import pickletools
import struct
from pathlib import Path
from typing import Any, Dict, List

NUMPY_MAGIC = b"\x93NUMPY"
HOSTILE_GLOBALS = {
    ("os", "system"), ("posix", "system"), ("nt", "system"),
    ("os", "popen"), ("subprocess", "Popen"), ("subprocess", "run"),
    ("subprocess", "call"), ("subprocess", "check_output"),
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "__import__"),
    ("__builtin__", "eval"), ("__builtin__", "exec"),
}


def _scan_pickle_bytes(payload: bytes, findings: List[Dict[str, Any]]) -> None:
    try:
        stack_strs: List[str] = []
        for op, arg, _ in pickletools.genops(io.BytesIO(payload)):
            if op.name == "GLOBAL" and isinstance(arg, str):
                parts = arg.split(" ", 1)
                if len(parts) == 2 and (parts[0], parts[1]) in HOSTILE_GLOBALS:
                    findings.append({
                        "severity": "MALICIOUS",
                        "type": "NUMPY_PICKLE_RCE",
                        "detail": f"Object-dtype .npy invokes hostile global {parts[0]}.{parts[1]}",
                    })
            elif op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE") and isinstance(arg, str):
                stack_strs.append(arg)
            elif op.name == "STACK_GLOBAL" and len(stack_strs) >= 2:
                mod, name = stack_strs[-2], stack_strs[-1]
                if (mod, name) in HOSTILE_GLOBALS:
                    findings.append({
                        "severity": "MALICIOUS",
                        "type": "NUMPY_PICKLE_RCE",
                        "detail": f"Object-dtype .npy invokes hostile STACK_GLOBAL {mod}.{name}",
                    })
    except Exception as e:
        findings.append({
            "severity": "SUSPICIOUS",
            "type": "NUMPY_PICKLE_MALFORMED",
            "detail": f"Could not fully disassemble embedded Pickle stream: {e}",
        })


def scan_numpy(path: str) -> Dict[str, Any]:
    p = Path(path)
    findings: List[Dict[str, Any]] = []
    descr = ""
    try:
        with p.open("rb") as f:
            magic = f.read(6)
            if magic != NUMPY_MAGIC:
                raise ValueError("Invalid NUMPY magic")
            major, minor = struct.unpack("<BB", f.read(2))
            if major == 1:
                (hlen,) = struct.unpack("<H", f.read(2))
            else:
                (hlen,) = struct.unpack("<I", f.read(4))
            hdr_text = f.read(hlen).decode("latin1").strip()
            hdr = ast.literal_eval(hdr_text)
            descr = str(hdr.get("descr", ""))
            if "O" in descr:
                payload = f.read(4 * 1024 * 1024)
                _scan_pickle_bytes(payload, findings)
                if not findings:
                    findings.append({
                        "severity": "SUSPICIOUS",
                        "type": "NUMPY_OBJECT_DTYPE",
                        "detail": f"NumPy array uses object dtype ({descr!r}) with embedded Pickle stream",
                    })
    except Exception as e:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.60,
            "format": "NUMPY",
            "summary": f"Malformed .npy header: {e}",
            "findings": [{"severity": "SUSPICIOUS", "type": "NUMPY_PARSE_ERROR", "detail": str(e)}],
            "features": {"format": "NUMPY", "parse_error": str(e)},
        }

    if any(f["severity"] == "MALICIOUS" for f in findings):
        verdict, conf = "MALICIOUS", 0.97
        summary = findings[0]["detail"]
    elif findings:
        verdict, conf = "SUSPICIOUS", 0.72
        summary = findings[0]["detail"]
    else:
        verdict, conf = "BENIGN", 0.98
        summary = f"Clean numeric NumPy array (descr={descr})"

    return {
        "verdict": verdict,
        "confidence": conf,
        "format": "NUMPY",
        "summary": summary,
        "findings": findings,
        "features": {"format": "NUMPY", "descr": descr},
    }

scan = scan_numpy
