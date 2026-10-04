"""
Vigilant HDF5 / Keras Inspector
===============================
Static scanner for Keras `.h5` models using h5py.

Checks:
  * decompression-bomb heuristics (uncompressed : stored ratio > 20:1)
  * Keras `Lambda` layers: base64-encoded `marshal` bytecode is extracted
    and disassembled with `dis`; dangerous global lookups (eval, exec, os,
    sys, subprocess, import) are flagged as RCE primitives.
"""
from __future__ import annotations

import base64
import dis
import io
import json
import marshal
import os
from typing import Any, Dict, List, Set

FORMAT = "HDF5"
COMPRESSION_RATIO_LIMIT = 20.0
DANGEROUS_GLOBALS = {
    "eval", "exec", "compile", "__import__", "open", "input",
    "os", "sys", "subprocess", "socket", "shutil", "ctypes",
    "pickle", "marshal", "builtins", "globals", "getattr", "setattr",
}


def _report(model_name: str, verdict: str, confidence: str, attack_vector: str,
            summary: str, **details: Any) -> Dict[str, Any]:
    return {
        "model_name": model_name, "format": FORMAT, "verdict": verdict,
        "confidence": confidence, "attack_vector": attack_vector,
        "summary": summary, "technical_details": details,
    }


def _analyze_lambda_code(encoded: str) -> Dict[str, Any]:
    """Decode a base64 marshal blob and audit its bytecode."""
    result: Dict[str, Any] = {"decoded": False, "dangerous_globals": [],
                              "opcodes_seen": []}
    try:
        raw = base64.b64decode(encoded)
        code = marshal.loads(raw)
    except Exception as exc:
        result["decode_error"] = str(exc)
        return result

    result["decoded"] = True
    names: Set[str] = set()
    opcodes: Set[str] = set()

    def walk(co) -> None:
        names.update(co.co_names)
        for instr in dis.get_instructions(co):
            opcodes.add(instr.opname)
        for const in co.co_consts:
            if hasattr(const, "co_code"):
                walk(const)

    walk(code)
    result["opcodes_seen"] = sorted(opcodes)
    result["dangerous_globals"] = sorted(names & DANGEROUS_GLOBALS)
    return result


def scan_hdf5(path: str) -> Dict[str, Any]:
    """Statically inspect an .h5/.keras HDF5 model. Returns telemetry."""
    name = os.path.basename(path)
    try:
        import h5py  # type: ignore
    except ImportError:
        return _report(name, "SUSPICIOUS", "LOW", "NONE",
                       "h5py is not installed; HDF5 inspection unavailable.",
                       error="h5py-missing")

    bomb_hits: List[str] = []
    lambda_findings: List[Dict[str, Any]] = []
    datasets = 0
    try:
        with h5py.File(path, "r") as h5:
            file_size = os.path.getsize(path)

            # ---- decompression bomb heuristic --------------------------- #
            total_uncompressed = 0
            compressed_payload = 0

            def visit_datasets(obj_name, obj):
                nonlocal datasets, total_uncompressed, compressed_payload
                if not hasattr(obj, "shape"):
                    return
                datasets += 1
                nbytes = int(obj.size) * obj.dtype.itemsize
                total_uncompressed += nbytes
                stored = obj.id.get_storage_size()
                if obj.compression and stored > 0:
                    compressed_payload += stored
                    ratio = nbytes / max(stored, 1)
                    if ratio > COMPRESSION_RATIO_LIMIT:
                        bomb_hits.append(
                            f"dataset '{obj_name}': {ratio:.1f}:1 "
                            f"({nbytes} B stored as {stored} B, "
                            f"compression={obj.compression})")

            h5.visititems(visit_datasets)

            if file_size > 0:
                global_ratio = total_uncompressed / file_size
                if global_ratio > COMPRESSION_RATIO_LIMIT:
                    bomb_hits.append(
                        f"file-level ratio {global_ratio:.1f}:1 "
                        f"({total_uncompressed} B uncompressed vs "
                        f"{file_size} B on disk)")

            # ---- Lambda layer bytecode audit ----------------------------- #
            if "model_config" in h5.attrs:
                raw_cfg = h5.attrs["model_config"]
                cfg_str = raw_cfg.decode("utf-8") if isinstance(raw_cfg, bytes) \
                    else str(raw_cfg)
                try:
                    cfg = json.loads(cfg_str)
                except json.JSONDecodeError as exc:
                    cfg = None
                    lambda_findings.append(
                        {"error": f"model_config not valid JSON: {exc}"})

                def walk_layers(node, trail=""):
                    if isinstance(node, dict):
                        if node.get("class_name") == "Lambda":
                            inner = node.get("config", {})
                            entry = {"layer": inner.get("name", trail),
                                     "function": None, "decode": None}
                            for field in ("function",):
                                blob = inner.get(field)
                                if isinstance(blob, str):
                                    entry["function"] = _analyze_lambda_code(blob)
                                elif isinstance(blob, (list, tuple)) and blob \
                                        and isinstance(blob[0], str):
                                    entry["function"] = _analyze_lambda_code(blob[0])
                            if entry["function"]:
                                lambda_findings.append(entry)
                        for k, v in node.items():
                            walk_layers(v, f"{trail}/{k}")
                    elif isinstance(node, list):
                        for i, v in enumerate(node):
                            walk_layers(v, f"{trail}[{i}]")

                if cfg is not None:
                    walk_layers(cfg)
    except Exception as exc:
        return _report(name, "SUSPICIOUS", "MEDIUM", "NONE",
                       f"HDF5 parse failed: {exc}", error=str(exc))

    dangerous = [f for f in lambda_findings
                 if f.get("function") and f["function"].get("dangerous_globals")]

    details = dict(dataset_count=datasets, bomb_indicators=bomb_hits,
                   lambda_layers=lambda_findings)

    if dangerous:
        return _report(name, "MALICIOUS", "HIGH", "LAMBDA_BYTECODE",
                       "Keras Lambda layer bytecode references dangerous "
                       "globals — arbitrary-code-execution primitive.",
                       **details)
    if bomb_hits:
        return _report(name, "MALICIOUS", "HIGH", "DOS_BOMB",
                       "HDF5 decompression-bomb pattern detected.", **details)
    if lambda_findings:
        return _report(name, "SUSPICIOUS", "MEDIUM", "LAMBDA_BYTECODE",
                       f"{len(lambda_findings)} Lambda layer(s) found but "
                       f"bytecode looks benign.", **details)
    return _report(name, "BENIGN", "HIGH", "NONE",
                   f"Clean HDF5/Keras model: {datasets} datasets, sane "
                   f"compression ratios, no Lambda layers.", **details)


if __name__ == "__main__":
    import sys
    print(json.dumps(scan_hdf5(sys.argv[1]), indent=2, default=str))
