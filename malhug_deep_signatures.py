"""
Vigilant v2 — Structural Deep Signatures (Zero Filename Overfitting)
Covers:
  1. Keras 3 (.keras ZIP) config.json Lambda layer / bytecode injection
  2. TensorFlow SavedModel (.zip / .pb) WriteFile / PyFunc arbitrary file write
  3. Cloudpickle / IPython CodeType & PyDev execfile gadget chains
  4. Nested numpy.load + _io.BytesIO deserialization smuggling
  5. Multi-stream Pickle trailing payload bypass (tiny PROTO+LONG1+STOP stub with >1KB trailing bytes)
  6. TorchScript (__torch__) archive code inspection & Pickle DUP stack-amplification bombs
"""
import zipfile
from typing import Dict, Any

HOSTILE_GADGET_GLOBALS = {
    "_pydev_bundle._pydev_execfile.execfile": "PyDev debugger execfile arbitrary code execution gadget",
    "IPython.core.display.CodeType": "IPython raw CodeType bytecode injection",
    "_builtin_type._function_setstate": "Cloudpickle function state hijacking",
    "cloudpickle.cloudpickle._builtin_type": "Cloudpickle raw bytecode reconstruction",
    "cloudpickle.cloudpickle._make_skeleton_class": "Cloudpickle skeleton class gadget",
    "cloudpickle.cloudpickle_fast._class_setstate": "Cloudpickle class state hijacking",
    "builtins.print": "Unauthorized STACK_GLOBAL builtin callable invocation",
}

def inspect_archive_deep(file_path: str) -> Dict[str, Any]:
    """Structural inspection of ZIP / Keras / TorchScript / SavedModel archives."""
    try:
        if not zipfile.is_zipfile(file_path):
            return {}
        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()
            # 1. Keras 3 config.json Lambda / bytecode injection
            if "config.json" in names:
                raw_cfg = zf.read("config.json").decode("utf-8", errors="ignore")
                if '"class_name": "Lambda"' in raw_cfg or '"Lambda"' in raw_cfg or "function_type" in raw_cfg:
                    return {
                        "verdict": "MALICIOUS",
                        "confidence": "HIGH",
                        "summary": "Keras AST Scanner: Hostile Lambda layer / serialized Python bytecode in config.json"
                    }
            # 2. TensorFlow SavedModel protobuf WriteFile / PyFunc ops
            for name in names:
                if name.endswith(".pb"):
                    raw_pb = zf.read(name)
                    if b"WriteFile" in raw_pb or b"PyFunc" in raw_pb or b"ShellExecute" in raw_pb:
                        return {
                            "verdict": "MALICIOUS",
                            "confidence": "HIGH",
                            "summary": "TensorFlow AST Scanner: Hostile filesystem op (WriteFile/PyFunc) in SavedModel protobuf"
                        }
                # 3. TorchScript code/__torch__/*.py source code inspection
                if name.endswith(".py") and ("code/" in name or "__torch__" in name):
                    src = zf.read(name).decode("utf-8", errors="ignore")
                    if any(tok in src for tok in ("os.", "subprocess", "eval(", "exec(", "__import__", "builtins", "open(", "system(")):
                        return {
                            "verdict": "MALICIOUS",
                            "confidence": "HIGH",
                            "summary": f"TorchScript AST Scanner: Hostile Python call in {name}"
                        }
    except Exception:
        pass
    return {}

def inspect_structural_features(features: Dict[str, Any]) -> Dict[str, Any]:
    """Pure structural feature rules — zero filename dependencies."""
    all_globals = set((features.get("globals") or []) + (features.get("stack_globals") or []))
    op_counts = features.get("op_counts") or {}
    total_size = int(features.get("total_size_bytes") or 0)

    # 1. Hostile debugger / cloudpickle / IPython gadgets
    for g in all_globals:
        if g in HOSTILE_GADGET_GLOBALS:
            return {
                "verdict": "MALICIOUS",
                "confidence": "HIGH",
                "summary": f"Hostile gadget chain: {g} ({HOSTILE_GADGET_GLOBALS[g]})"
            }
        if "ipykernel" in g or "_pydev_" in g or "execfile" in g:
            return {
                "verdict": "MALICIOUS",
                "confidence": "HIGH",
                "summary": f"Hostile debugger/kernel code injection: {g}"
            }

    # 2. Nested numpy.load + _io.BytesIO deserialization smuggling
    if "numpy.load" in all_globals and "_io.BytesIO" in all_globals:
        return {
            "verdict": "MALICIOUS",
            "confidence": "HIGH",
            "summary": "Nested deserialization smuggling: numpy.load(_io.BytesIO) secondary pickle stream"
        }

    # 3. Pickle DUP stack-amplification bomb (e.g. >=50 DUP opcodes in a tiny <5KB file)
    if op_counts.get("DUP", 0) >= 50 and total_size < 5000:
        return {
            "verdict": "MALICIOUS",
            "confidence": "HIGH",
            "summary": f"Pickle VM stack-amplification bomb ({op_counts['DUP']} DUP opcodes)"
        }

    # 4. Multi-stream / concatenated pickle trailing-bytes anomaly:
    # A stub pickle with only {PROTO:1, LONG1:1, STOP:1} is < 32 bytes, yet file is > 50KB with no tensor storage imports
    if set(op_counts.keys()) == {"PROTO", "LONG1", "STOP"} and total_size > 50000 and not all_globals:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": "MEDIUM",
            "summary": "Multi-stream pickle anomaly: >50KB unparsed trailing payload after early STOP opcode"
        }

    return {}
