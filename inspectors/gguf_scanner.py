"""
Pure-Python GGUF Binary Header & Jinja2 SSTI Security Scanner (Zero External Dependencies).
Parses GGUF v1/v2/v3 header + KV metadata table in <5ms while skipping multi-GB tensor weights.
Detects:
  1. Integer overflow / OOM allocation attacks in tensor_count / kv_count
  2. CVE-2024-34359 Jinja2 Server-Side Template Injection (SSTI) in tokenizer.chat_template
  3. Obfuscated dunder / gadget-chain payloads inside template expressions
"""
from __future__ import annotations
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Tuple

GGUF_MAGIC = b"GGUF"
MAX_TENSORS = 1_000_000
MAX_KV_PAIRS = 100_000
MAX_STR_LEN = 4 * 1024 * 1024

# GGUF scalar byte sizes by type ID
SCALAR_SIZES = {
    0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1,
    10: 8, 11: 8, 12: 8,
}

SSTI_CRITICAL = re.compile(
    r"(__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|"
    r"os\.popen|os\.system|subprocess|eval\s*\(|exec\s*\(|open\s*\(|"
    r"cycler\.__init__|joiner\.__init__|namespace\.__init__|lipsum\.__globals__|"
    r"\\x5f\\x5f|\\u005f\\u005f)",
    re.IGNORECASE,
)
SSTI_SUSPICIOUS = re.compile(
    r"(\|attr\s*\(|__init__|__dict__|__base__|request\.application|config\.items)",
    re.IGNORECASE,
)


def _read_exact(f, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise ValueError("Unexpected EOF while parsing GGUF header")
    return b


def _read_str(f) -> str:
    (length,) = struct.unpack("<Q", _read_exact(f, 8))
    if length > MAX_STR_LEN:
        raise ValueError(f"Abnormally large GGUF string length: {length}")
    return _read_exact(f, length).decode("utf-8", errors="replace")


def _skip_or_read_val(f, vtype: int, keep: bool = False) -> Any:
    if vtype in SCALAR_SIZES:
        raw = _read_exact(f, SCALAR_SIZES[vtype])
        return raw if keep else None
    if vtype == 8:  # STRING
        return _read_str(f)
    if vtype == 9:  # ARRAY
        elem_type, count = struct.unpack("<IQ", _read_exact(f, 12))
        if count > 5_000_000:
            raise ValueError(f"Abnormally large GGUF array count: {count}")
        if elem_type in SCALAR_SIZES:
            f.seek(SCALAR_SIZES[elem_type] * count, 1)
            return None
        for _ in range(count):
            _skip_or_read_val(f, elem_type, keep=False)
        return None
    raise ValueError(f"Unknown GGUF value type: {vtype}")


def _analyze_chat_template(tpl: str, findings: List[Dict[str, Any]]) -> None:
    exprs = re.findall(r"(\{\{.*?\}\}|\{%.*?%\})", tpl, flags=re.DOTALL)
    joined = "\n".join(exprs) if exprs else tpl

    crit = SSTI_CRITICAL.findall(joined)
    if crit:
        findings.append({
            "severity": "MALICIOUS",
            "type": "GGUF_JINJA2_SSTI",
            "detail": f"Critical Jinja2 SSTI gadget(s) in chat_template: {sorted(set(crit))[:6]}",
        })
        return

    susp = SSTI_SUSPICIOUS.findall(joined)
    if susp:
        findings.append({
            "severity": "SUSPICIOUS",
            "type": "GGUF_JINJA2_SUSPICIOUS",
            "detail": f"Suspicious Jinja2 reflection primitives in chat_template: {sorted(set(susp))[:6]}",
        })


def scan_gguf(path: str) -> Dict[str, Any]:
    p = Path(path)
    findings: List[Dict[str, Any]] = []
    meta_summary: Dict[str, Any] = {}

    try:
        with p.open("rb") as f:
            magic = _read_exact(f, 4)
            if magic != GGUF_MAGIC:
                raise ValueError(f"Invalid GGUF magic: {magic!r}")
            version, tensor_count, kv_count = struct.unpack("<IQQ", _read_exact(f, 20))
            meta_summary = {"version": version, "tensor_count": tensor_count, "kv_count": kv_count}

            if tensor_count > MAX_TENSORS or kv_count > MAX_KV_PAIRS:
                findings.append({
                    "severity": "MALICIOUS",
                    "type": "GGUF_HEADER_OVERFLOW",
                    "detail": f"GGUF header integer overflow / OOM DoS (tensors={tensor_count}, kv={kv_count})",
                })
            else:
                for _ in range(kv_count):
                    key = _read_str(f)
                    (vtype,) = struct.unpack("<I", _read_exact(f, 4))
                    is_tpl = "chat_template" in key.lower()
                    val = _skip_or_read_val(f, vtype, keep=is_tpl)
                    if is_tpl and isinstance(val, str):
                        meta_summary["has_chat_template"] = True
                        _analyze_chat_template(val, findings)
    except Exception as e:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.60,
            "format": "GGUF",
            "summary": f"Malformed GGUF container: {e}",
            "findings": [{"severity": "SUSPICIOUS", "type": "GGUF_PARSE_ERROR", "detail": str(e)}],
            "features": {"format": "GGUF", "parse_error": str(e), **meta_summary},
        }

    has_mal = any(f["severity"] == "MALICIOUS" for f in findings)
    has_susp = any(f["severity"] == "SUSPICIOUS" for f in findings)

    if has_mal:
        verdict, conf = "MALICIOUS", 0.97
        summary = f"Hostile GGUF payload detected ({findings[0]['type']}): {findings[0]['detail']}"
    elif has_susp:
        verdict, conf = "SUSPICIOUS", 0.72
        summary = f"Suspicious GGUF chat_template requires review: {findings[0]['detail']}"
    else:
        verdict, conf = "BENIGN", 0.96
        summary = f"Clean GGUF v{meta_summary.get('version')} container (tensors={meta_summary.get('tensor_count')}, kv={meta_summary.get('kv_count')})"

    return {
        "verdict": verdict,
        "confidence": conf,
        "format": "GGUF",
        "summary": summary,
        "findings": findings,
        "features": {"format": "GGUF", **meta_summary},
    }

scan = scan_gguf
inspect_gguf = scan_gguf
