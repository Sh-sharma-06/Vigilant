import base64
import dis
import io
import json
import marshal
import math
import os
import struct
import zipfile
from collections import Counter
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# 1. Information-Theoretic Sliding-Window Entropy Profiler
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def compute_entropy_profile(file_path: str, window_size: int = 65536, max_windows: int = 32) -> Dict[str, float]:
    """Computes sliding-window Shannon entropy to detect encrypted/XOR-packed shellcode or spoofed headers."""
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {"mean_entropy": 0.0, "max_entropy": 0.0, "high_entropy_windows": 0}
        entropies = []
        with open(file_path, "rb") as f:
            for _ in range(max_windows):
                chunk = f.read(window_size)
                if not chunk:
                    break
                entropies.append(shannon_entropy(chunk))
        if not entropies:
            return {"mean_entropy": 0.0, "max_entropy": 0.0, "high_entropy_windows": 0}
        return {
            "mean_entropy": round(sum(entropies) / len(entropies), 4),
            "max_entropy": round(max(entropies), 4),
            "high_entropy_windows": sum(1 for e in entropies if e > 7.95),
        }
    except Exception:
        return {"mean_entropy": 0.0, "max_entropy": 0.0, "high_entropy_windows": 0}

# ---------------------------------------------------------------------------
# 2. Magic-Byte True Format Classifier
# ---------------------------------------------------------------------------
def identify_format(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    try:
        with open(file_path, "rb") as f:
            header = f.read(64)
    except Exception:
        return "UNKNOWN"

    if header.startswith(b"\x89HDF\r\n\x1a\n"):
        return "HDF5"
    if header.startswith(b"GGUF"):
        return "GGUF"
    if header.startswith(b"7z\xbc\xaf'\x1c") or ext == ".7z":
        return "7Z"
    if ext == ".safetensors":
        return "SAFETENSORS"
    if ext == ".onnx":
        return "ONNX"
    if header.startswith(b"PK\x03\x04") or zipfile.is_zipfile(file_path):
        return "ZIP"
    if len(header) >= 8:
        # Check Safetensors header structure: 8-byte little-endian uint64 JSON length followed by '{'
        json_len = struct.unpack("<Q", header[:8])[0]
        if 2 <= json_len <= 100 * 1024 * 1024 and header[8:9] == b"{":
            return "SAFETENSORS"
    if header.startswith(b"\x80") and len(header) >= 2 and header[1] in (1, 2, 3, 4, 5):
        return "PICKLE"
    return "PICKLE" if ext in (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib") else "UNKNOWN"

# ---------------------------------------------------------------------------
# 3. HDF5 / Keras AST & Marshal Bytecode Inspector
# ---------------------------------------------------------------------------
DANGEROUS_CODE_NAMES = {
    "os", "sys", "subprocess", "posix", "nt", "builtins", "__builtin__",
    "eval", "exec", "compile", "__import__", "getattr", "popen", "system",
    "socket", "urllib", "requests", "shutil", "pty", "ctypes", "marshal", "pickle"
}

def _inspect_code_object(code_obj, findings: List[str]):
    """Recursively disassembles Python marshal CodeType objects hidden inside Keras Lambda layers."""
    for name in getattr(code_obj, "co_names", ()):
        if name in DANGEROUS_CODE_NAMES:
            findings.append(f"Keras Lambda bytecode references dangerous symbol: {name}")
    for const in getattr(code_obj, "co_consts", ()):
        if hasattr(const, "co_code"):
            _inspect_code_object(const, findings)
        elif isinstance(const, str) and any(cmd in const for cmd in ("/bin/sh", "/bin/bash", "sh -c", "curl ", "wget ", "eval(", "exec(")):
            findings.append(f"Keras Lambda bytecode constant contains shell payload: {const[:60]}")

def _walk_keras_config(node: Any, findings: List[str]):
    if isinstance(node, dict):
        cls_name = node.get("class_name", "")
        if cls_name == "Lambda":
            findings.append("Suspicious Keras Lambda layer present in model architecture")
            cfg = node.get("config", {})
            fn_blob = cfg.get("function")
            # Keras serializes Lambda functions as base64-encoded marshal bytecode or tuple
            raw_b64 = fn_blob[0] if isinstance(fn_blob, (list, tuple)) and fn_blob else fn_blob
            if isinstance(raw_b64, str):
                try:
                    decoded = base64.b64decode(raw_b64.encode("utf-8"))
                    code_obj = marshal.loads(decoded)
                    _inspect_code_object(code_obj, findings)
                except Exception as e:
                    if any(k in raw_b64 for k in ("os", "system", "subprocess", "eval", "exec")):
                        findings.append(f"Obfuscated Keras Lambda payload: {str(e)}")
        for v in node.values():
            _walk_keras_config(v, findings)
    elif isinstance(node, list):
        for item in node:
            _walk_keras_config(item, findings)

def scan_hdf5(file_path: str) -> Dict[str, Any]:
    findings = []
    try:
        import h5py
        with h5py.File(file_path, "r") as f:
            for attr_name in ("model_config", "training_config"):
                if attr_name in f.attrs:
                    raw = f.attrs[attr_name]
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="ignore")
                    cfg = json.loads(raw)
                    _walk_keras_config(cfg, findings)
    except Exception as e:
        return {"is_malicious": True, "reasons": [f"Malformed HDF5 container: {str(e)}"]}

    return {"is_malicious": len(findings) > 0, "reasons": findings}

# ---------------------------------------------------------------------------
# 4. ONNX Computational Graph & External Data Lexical Boundary Verifier
# ---------------------------------------------------------------------------
def scan_onnx(file_path: str) -> Dict[str, Any]:
    findings = []
    try:
        import onnx
        model = onnx.load(file_path, load_external_data=False)
        base_dir = os.path.realpath(os.path.dirname(file_path))

        # 1. Check external tensor locations for CVE-2024-27318 path traversal / SSRF
        for tensor in model.graph.initializer:
            if tensor.data_location == onnx.TensorProto.EXTERNAL:
                ext_map = {entry.key: entry.value for entry in tensor.external_data}
                loc = ext_map.get("location", "")
                if ".." in loc or loc.startswith(("/", "\\", "http://", "https://", "ftp://")):
                    findings.append(f"ONNX external tensor path traversal / SSRF attempt: {loc}")
                else:
                    resolved = os.path.realpath(os.path.join(base_dir, loc))
                    if not resolved.startswith(base_dir + os.sep) and resolved != base_dir:
                        findings.append(f"ONNX external tensor escapes model directory: {loc}")

        # 2. Check custom operator domains and suspicious node attributes
        standard_domains = {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"}
        for node in model.graph.node:
            if node.domain not in standard_domains:
                findings.append(f"Non-standard ONNX custom operator domain: {node.domain}::{node.op_type}")
            if node.op_type in ("PyOp", "PythonOp", "CustomOp"):
                findings.append(f"Arbitrary code execution ONNX operator: {node.op_type}")
    except Exception as e:
        return {"is_malicious": True, "reasons": [f"Malformed or hostile ONNX protobuf: {str(e)}"]}

    return {"is_malicious": len(findings) > 0, "reasons": findings}

# ---------------------------------------------------------------------------
# 5. GGUF Header Allocation & Jinja2 Chat-Template AST Verifier
# ---------------------------------------------------------------------------
def _verify_jinja_ast(template_str: str, findings: List[str]):
    """Parses GGUF chat_template into a Jinja2 AST to detect CVE-2024-34359 SSTI sandbox escapes."""
    if any(tok in template_str for tok in ("__globals__", "__subclasses__", "__builtins__", "__import__", "__mro__", "popen", "os.system")):
        findings.append("GGUF Jinja2 chat_template SSTI sandbox escape detected")
    try:
        from jinja2 import Environment, nodes
        env = Environment()
        ast = env.parse(template_str)
        for node in ast.find_all(nodes.Getattr):
            if node.attr.startswith("__") or node.attr in ("popen", "system", "eval", "exec", "subprocess"):
                findings.append(f"GGUF Jinja2 AST accesses restricted attribute: {node.attr}")
    except Exception as e:
        findings.append(f"Malformed GGUF Jinja2 chat_template syntax: {str(e)}")

def scan_gguf(file_path: str) -> Dict[str, Any]:
    findings = []
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if magic != b"GGUF":
                return {"is_malicious": True, "reasons": ["Invalid GGUF magic header"]}
            version, tensor_count, kv_count = struct.unpack("<IQQ", f.read(20))
            if version not in (1, 2, 3):
                findings.append(f"Unsupported/spoofed GGUF version: {version}")
            # Defend against heap-allocation integer overflow DoS
            if tensor_count > 1_000_000 or kv_count > 1_000_000 or (tensor_count * 32) > file_size:
                findings.append(f"GGUF header integer overflow allocation attack (tensors={tensor_count}, kv={kv_count})")

            # Scan metadata section for SSTI in chat_template or embedded shell payloads
            raw_meta = f.read(min(file_size - 24, 2 * 1024 * 1024)).decode("utf-8", errors="ignore")
            if "chat_template" in raw_meta or "{{" in raw_meta or "{%" in raw_meta:
                _verify_jinja_ast(raw_meta, findings)
    except Exception as e:
        return {"is_malicious": True, "reasons": [f"Corrupted GGUF header: {str(e)}"]}

    return {"is_malicious": len(findings) > 0, "reasons": findings}

# ---------------------------------------------------------------------------
# 6. Safetensors Structural Header & Offset Verifier
# ---------------------------------------------------------------------------
def scan_safetensors(file_path: str) -> Dict[str, Any]:
    findings = []
    try:
        file_size = os.path.getsize(file_path)
        if file_size < 8:
            return {"is_malicious": True, "reasons": ["Truncated Safetensors header"]}
        with open(file_path, "rb") as f:
            header_len = struct.unpack("<Q", f.read(8))[0]
            if header_len == 0 or header_len > 100 * 1024 * 1024 or (8 + header_len) > file_size:
                return {"is_malicious": True, "reasons": [f"Safetensors header length out-of-bounds: {header_len}"]}
            header_bytes = f.read(header_len)
            header_json = json.loads(header_bytes.decode("utf-8"))
            if not isinstance(header_json, dict):
                return {"is_malicious": True, "reasons": ["Safetensors header is not a JSON object"]}

            data_base = 8 + header_len
            for key, val in header_json.items():
                if key == "__metadata__":
                    meta_str = json.dumps(val)
                    if any(s in meta_str for s in ("__import__", "os.system", "eval(", "exec(", "/bin/sh")):
                        findings.append("Suspicious executable string inside Safetensors __metadata__")
                    continue
                if isinstance(val, dict) and "data_offsets" in val:
                    offsets = val["data_offsets"]
                    if len(offsets) != 2 or offsets[0] > offsets[1] or (data_base + offsets[1]) > file_size:
                        findings.append(f"Safetensors tensor '{key}' out-of-bounds data_offsets: {offsets}")
    except Exception as e:
        return {"is_malicious": True, "reasons": [f"Invalid Safetensors structure: {str(e)}"]}

    return {"is_malicious": len(findings) > 0, "reasons": findings}
