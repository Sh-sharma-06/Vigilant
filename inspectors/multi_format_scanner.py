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

# 4. ONNX Computational Graph & External Data Security Scanner
# ---------------------------------------------------------------------------

BUILTIN_ONNX_DOMAINS = {
    "",
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.preview.training",
    "com.microsoft",
    "com.microsoft.experimental",
    "com.microsoft.nchwc",
    "com.microsoft.dml",
    "org.pytorch",
    "ai.onnx.contrib",
}


def scan_onnx(file_path: str) -> Dict[str, Any]:

    findings = []
    suspicious_notes = []

    try:
        import onnx

        model = onnx.load(
            file_path,
            load_external_data=False
        )

        base_dir = os.path.realpath(
            os.path.dirname(os.path.abspath(file_path))
        )

        # 1. Validate external tensor locations.
        for tensor in model.graph.initializer:

            if tensor.data_location != onnx.TensorProto.EXTERNAL:
                continue

            ext_map = {
                entry.key: entry.value
                for entry in tensor.external_data
            }

            location = ext_map.get("location", "")

            if not location:
                findings.append(
                    "ONNX external tensor has an empty location"
                )
                continue

            normalized = location.replace("\\", "/")

            # Reject absolute, remote and traversal paths.
            if (
                ".." in normalized.split("/")
                or normalized.startswith("/")
                or normalized.startswith("//")
                or "://" in normalized
                or (
                    len(normalized) >= 2
                    and normalized[1] == ":"
                )
            ):
                findings.append(
                    "ONNX external tensor path traversal or "
                    f"remote path detected: {location}"
                )
                continue

            resolved = os.path.realpath(
                os.path.join(base_dir, location)
            )

            try:
                inside_directory = (
                    os.path.commonpath(
                        [base_dir, resolved]
                    ) == base_dir
                )
            except ValueError:
                inside_directory = False

            if not inside_directory:
                findings.append(
                    "ONNX external tensor escapes model "
                    f"directory: {location}"
                )

        # 2. Inspect graph operators and domains.
        for node in model.graph.node:

            domain = (node.domain or "").strip()

            # Explicitly dangerous operator names.
            if node.op_type in (
                "PyOp",
                "PythonOp",
                "CustomOp",
            ):
                findings.append(
                    "Potential arbitrary code execution "
                    f"ONNX operator: {node.op_type}"
                )
                continue

            # Known ONNX Runtime and framework domains are allowed.
            if domain in BUILTIN_ONNX_DOMAINS:
                continue

            # Unknown domains are NOT automatically malicious.
            # Look for additional suspicious evidence.
            attr_str = " ".join(
                str(attribute)
                for attribute in node.attribute
            ).lower()

            dangerous_markers = (
                ".so",
                ".dll",
                ".dylib",
                ".py",
                "os.system",
                "subprocess",
            )

            if any(
                marker in attr_str
                for marker in dangerous_markers
            ):
                findings.append(
                    "Unknown ONNX custom operator contains "
                    f"potential executable payload: "
                    f"{domain}::{node.op_type}"
                )
            else:
                suspicious_notes.append(
                    "Unrecognized ONNX operator domain: "
                    f"{domain}::{node.op_type}"
                )

    except Exception as exc:
        return {
            "is_malicious": False,
            "is_suspicious": True,
            "reasons": [
                f"Malformed or unreadable ONNX model: {str(exc)}"
            ],
        }

    return {
        "is_malicious": bool(findings),
        "is_suspicious": (
            not findings and bool(suspicious_notes)
        ),
        "reasons": findings if findings else suspicious_notes,
    }


# ---------------------------------------------------------------------------
# 5. GGUF Header & Chat Template Security Scanner
# ------------------------------------------------

import os
import struct

GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_BOOL = 7
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_INT64 = 11
GGUF_TYPE_FLOAT64 = 12

_GGUF_SCALAR_SIZES = {
    0: 1,
    1: 1,
    2: 2,
    3: 2,
    4: 4,
    5: 4,
    6: 4,
    7: 1,
    10: 8,
    11: 8,
    12: 8,
}

_GGUF_MAX_STRING = 512_000
_GGUF_MAX_KEY = 4096
_GGUF_MAX_ARRAY = 1_000_000
_GGUF_MAX_KV = 100_000
_GGUF_MAX_DEPTH = 4


def _gguf_read_exact(f, size, file_size):
    if size < 0 or size > file_size - f.tell():
        raise ValueError("GGUF read exceeds file boundary")

    data = f.read(size)

    if len(data) != size:
        raise ValueError("Truncated GGUF data")

    return data


def _gguf_seek(f, size, file_size):
    if size < 0 or size > file_size - f.tell():
        raise ValueError("GGUF seek exceeds file boundary")

    f.seek(size, os.SEEK_CUR)


def _gguf_read_string(f, file_size, maximum=_GGUF_MAX_STRING):
    raw_length = _gguf_read_exact(f, 8, file_size)
    (length,) = struct.unpack("<Q", raw_length)

    if length > maximum:
        raise ValueError(
            f"GGUF string length exceeds limit: {length}"
        )

    return _gguf_read_exact(f, length, file_size)


def _skip_gguf_value(f, vtype, file_size, depth=0):
    if depth > _GGUF_MAX_DEPTH:
        raise ValueError("GGUF array nesting too deep")

    if vtype in _GGUF_SCALAR_SIZES:
        _gguf_seek(
            f,
            _GGUF_SCALAR_SIZES[vtype],
            file_size
        )
        return

    if vtype == GGUF_TYPE_STRING:
        _gguf_read_string(f, file_size)
        return

    if vtype == GGUF_TYPE_ARRAY:
        elem_type, count = struct.unpack(
            "<IQ",
            _gguf_read_exact(f, 12, file_size)
        )

        if count > _GGUF_MAX_ARRAY:
            raise ValueError("GGUF array exceeds safety limit")

        if elem_type in _GGUF_SCALAR_SIZES:
            total_size = _GGUF_SCALAR_SIZES[elem_type] * count
            _gguf_seek(f, total_size, file_size)

        else:
            for _ in range(count):
                _skip_gguf_value(
                    f,
                    elem_type,
                    file_size,
                    depth + 1
                )
        return

    raise ValueError(f"Unknown GGUF value type: {vtype}")


def _extract_gguf_chat_templates(f, kv_count, file_size):
    """
    Parse GGUF key-value metadata using binary length prefixes.

    ONLY tokenizer.chat_template metadata is extracted.

    tokenizer.ggml.tokens and all other tokenizer metadata
    are skipped without decoding or parsing as Jinja2.
    """
    templates = []

    if kv_count > _GGUF_MAX_KV:
        raise ValueError("GGUF metadata count exceeds safety limit")

    for _ in range(kv_count):

        key_bytes = _gguf_read_string(
            f,
            file_size,
            maximum=_GGUF_MAX_KEY
        )

        key = key_bytes.decode("utf-8", errors="strict")

        (vtype,) = struct.unpack(
            "<I",
            _gguf_read_exact(f, 4, file_size)
        )

        is_chat_template = (
            key == "tokenizer.chat_template"
            or key.startswith("tokenizer.chat_template.")
        )

        if not is_chat_template:
            _skip_gguf_value(f, vtype, file_size)
            continue

        if vtype == GGUF_TYPE_STRING:
            raw = _gguf_read_string(f, file_size)
            templates.append(
                raw.decode("utf-8", errors="replace")
            )

        elif vtype == GGUF_TYPE_ARRAY:

            elem_type, count = struct.unpack(
                "<IQ",
                _gguf_read_exact(f, 12, file_size)
            )

            if elem_type != GGUF_TYPE_STRING:
                _skip_gguf_value_contents = False
                raise ValueError(
                    "Chat template array must contain strings"
                )

            if count > 64:
                raise ValueError(
                    "Too many chat templates in GGUF metadata"
                )

            for _ in range(count):
                raw = _gguf_read_string(f, file_size)
                templates.append(
                    raw.decode("utf-8", errors="replace")
                )

        else:
            raise ValueError(
                f"Unexpected chat template value type: {vtype}"
            )

    return templates


def _verify_jinja_ast(template_str, findings, suspicious_notes):
    """
    Inspect only genuine chat-template strings.

    Static inspection is heuristic: it does not execute the template
    and does not prove that a sandbox escape is exploitable.
    """

    ssti_primitives = (
        "__globals__",
        "__subclasses__",
        "__builtins__",
        "__import__",
        "__mro__",
        "__class__",
        "os.system",
        "popen",
    )

    detected = [
        token
        for token in ssti_primitives
        if token in template_str
    ]

    if detected:
        findings.append(
            "GGUF chat template contains potential SSTI "
            "sandbox escape primitives: "
            + ", ".join(detected)
        )

    try:
        from jinja2 import Environment, nodes

        environment = Environment()
        parsed = environment.parse(template_str)

        for node in parsed.find_all(nodes.Getattr):

            if (
                node.attr.startswith("__")
                or node.attr in (
                    "popen",
                    "system",
                    "eval",
                    "exec",
                    "subprocess",
                )
            ):
                reason = (
                    "GGUF Jinja2 AST accesses restricted attribute: "
                    + node.attr
                )

                if reason not in findings:
                    findings.append(reason)

    except Exception as exc:
        suspicious_notes.append(
            "Non-standard GGUF chat template syntax: "
            + str(exc)[:120]
        )


def scan_gguf(file_path: str) -> Dict[str, Any]:

    findings = []
    suspicious_notes = []

    try:
        file_size = os.path.getsize(file_path)

        with open(file_path, "rb") as f:

            magic = _gguf_read_exact(f, 4, file_size)

            if magic != b"GGUF":
                return {
                    "is_malicious": True,
                    "is_suspicious": False,
                    "reasons": ["Invalid GGUF magic header"],
                }

            version, tensor_count, kv_count = struct.unpack(
                "<IQQ",
                _gguf_read_exact(f, 20, file_size)
            )

            if version not in (1, 2, 3):
                findings.append(
                    f"Unsupported GGUF version: {version}"
                )

            if tensor_count > 1_000_000:
                findings.append(
                    f"Excessive GGUF tensor count: {tensor_count}"
                )

            if kv_count > _GGUF_MAX_KV:
                findings.append(
                    f"Excessive GGUF metadata count: {kv_count}"
                )

            if findings:
                return {
                    "is_malicious": True,
                    "is_suspicious": False,
                    "reasons": findings,
                }

            templates = _extract_gguf_chat_templates(
                f,
                kv_count,
                file_size
            )

            for template in templates:
                _verify_jinja_ast(
                    template,
                    findings,
                    suspicious_notes
                )

    except Exception as exc:
        return {
            "is_malicious": False,
            "is_suspicious": True,
            "reasons": [
                f"Malformed or unreadable GGUF: {str(exc)[:160]}"
            ],
        }

    return {
        "is_malicious": bool(findings),
        "is_suspicious": (
            not findings and bool(suspicious_notes)
        ),
        "reasons": findings if findings else suspicious_notes,
    }


# ------------------------------------------------
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
