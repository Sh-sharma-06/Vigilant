"""
Dual-Engine HDF5 / Legacy Keras (.h5) Security Scanner.
Works with h5py if installed, OR falls back to a Pure-Python HDF5 Superblock & JSON Metadata Carver.
Routes any discovered Keras Lambda layers through 3-tier bytecode inspection:
  - Pure numeric weights -> BENIGN
  - Benign Lambda (e.g., tf.concat) -> SUSPICIOUS (REVIEW)
  - Hostile Lambda (os.system, subprocess, eval, exec) -> MALICIOUS
"""
from __future__ import annotations
import base64
import dis
import json
import marshal
import re
from pathlib import Path
from typing import Any, Dict, List

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
HOSTILE_CALLS = {
    "system", "popen", "exec", "eval", "compile", "__import__",
    "Popen", "run", "call", "check_output", "spawn", "urlopen", "socket",
}


def _inspect_lambda_bytecode(b64_code: str, layer_name: str, findings: List[Dict[str, Any]]) -> None:
    try:
        raw = base64.b64decode(b64_code)
        code_obj = marshal.loads(raw)
        names = set(getattr(code_obj, "co_names", ()))
        consts = [str(c) for c in getattr(code_obj, "co_consts", ()) if isinstance(c, str)]
        hits = sorted(names & HOSTILE_CALLS)
        if hits:
            findings.append({
                "severity": "MALICIOUS",
                "type": "HDF5_HOSTILE_LAMBDA",
                "detail": f"Keras Lambda {layer_name!r} invokes hostile symbols: {hits}",
                "co_names": sorted(names),
                "co_consts": consts[:10],
            })
        else:
            findings.append({
                "severity": "SUSPICIOUS",
                "type": "HDF5_BENIGN_LAMBDA",
                "detail": f"Keras Lambda {layer_name!r} contains executable bytecode (review recommended)",
                "co_names": sorted(names),
                "co_consts": consts[:10],
            })
    except Exception as e:
        findings.append({
            "severity": "SUSPICIOUS",
            "type": "HDF5_LAMBDA_UNREADABLE",
            "detail": f"Keras Lambda {layer_name!r} bytecode could not be disassembled: {e}",
        })


def _walk_keras_config(obj: Any, findings: List[Dict[str, Any]]) -> None:
    if isinstance(obj, dict):
        cls = str(obj.get("class_name", ""))
        cfg = obj.get("config", {})
        if cls == "Lambda" and isinstance(cfg, dict):
            lname = str(cfg.get("name", "lambda"))
            fn = cfg.get("function")
            if isinstance(fn, list) and fn and isinstance(fn[0], str):
                _inspect_lambda_bytecode(fn[0], lname, findings)
            elif isinstance(fn, str):
                _inspect_lambda_bytecode(fn, lname, findings)
            else:
                findings.append({
                    "severity": "SUSPICIOUS",
                    "type": "HDF5_LAMBDA_LAYER",
                    "detail": f"Keras Lambda layer {lname!r} present in model_config",
                })
        for v in obj.values():
            _walk_keras_config(v, findings)
    elif isinstance(obj, list):
        for item in obj:
            _walk_keras_config(item, findings)


def _carve_model_configs_pure_python(path: Path) -> List[Dict[str, Any]]:
    """Carves JSON model_config objects from HDF5 metadata without needing h5py."""
    configs: List[Dict[str, Any]] = []
    # Read first 8MB + last 2MB where HDF5 root attributes & object headers reside
    size = path.stat().st_size
    chunks = []
    with path.open("rb") as f:
        chunks.append(f.read(min(size, 8 * 1024 * 1024)))
        if size > 8 * 1024 * 1024:
            f.seek(max(0, size - 2 * 1024 * 1024))
            chunks.append(f.read())
    blob = b"".join(chunks)

    decoder = json.JSONDecoder()
    for m in re.finditer(rb'\{"class_name"\s*:\s*"', blob):
        start = m.start()
        try:
            text = blob[start:start + 2 * 1024 * 1024].decode("utf-8", errors="ignore")
            obj, _ = decoder.raw_decode(text)
            if isinstance(obj, dict):
                configs.append(obj)
        except Exception:
            continue
    return configs


def scan_hdf5(path: str) -> Dict[str, Any]:
    p = Path(path)
    findings: List[Dict[str, Any]] = []
    engine = "pure_python_carver"

    try:
        with p.open("rb") as f:
            head = f.read(16)
        if not head.startswith(HDF5_MAGIC):
            return {
                "verdict": "SUSPICIOUS",
                "confidence": 0.60,
                "format": "HDF5",
                "summary": "Invalid HDF5 superblock magic bytes",
                "findings": [{"severity": "SUSPICIOUS", "type": "HDF5_BAD_MAGIC", "detail": repr(head[:8])}],
                "features": {"format": "HDF5", "engine": engine},
            }

        configs: List[Dict[str, Any]] = []
        try:
            import h5py  # type: ignore
            engine = "h5py"
            with h5py.File(str(p), "r") as hf:
                for attr_name in ("model_config", "training_config"):
                    if attr_name in hf.attrs:
                        raw = hf.attrs[attr_name]
                        if isinstance(raw, bytes):
                            raw = raw.decode("utf-8", errors="replace")
                        configs.append(json.loads(raw))
        except ImportError:
            configs = _carve_model_configs_pure_python(p)

        for cfg in configs:
            _walk_keras_config(cfg, findings)

    except Exception as e:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.60,
            "format": "HDF5",
            "summary": f"HDF5 inspection error: {e}",
            "findings": [{"severity": "SUSPICIOUS", "type": "HDF5_PARSE_ERROR", "detail": str(e)}],
            "features": {"format": "HDF5", "engine": engine, "parse_error": str(e)},
        }

    has_mal = any(f["severity"] == "MALICIOUS" for f in findings)
    has_susp = any(f["severity"] == "SUSPICIOUS" for f in findings)

    if has_mal:
        verdict, conf = "MALICIOUS", 0.96
        summary = f"Hostile Keras Lambda payload in HDF5 ({findings[0]['detail']})"
    elif has_susp:
        verdict, conf = "SUSPICIOUS", 0.72
        summary = f"HDF5 model contains executable Lambda layer requiring review ({findings[0]['detail']})"
    else:
        verdict, conf = "BENIGN", 0.95
        summary = f"Clean HDF5 container (engine={engine}, configs_inspected={len(configs)})"

    return {
        "verdict": verdict,
        "confidence": conf,
        "format": "HDF5",
        "summary": summary,
        "findings": findings,
        "features": {"format": "HDF5", "engine": engine, "configs_inspected": len(configs)},
    }

scan = scan_hdf5
inspect_hdf5 = scan_hdf5
