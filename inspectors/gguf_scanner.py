"""
Vigilant GGUF Inspector
=======================
Raw-binary GGUF parser with zero external dependencies.

Validates the header (magic / version / counts) and walks every metadata
key-value pair with strict bounds checking so crafted files cannot trigger
buffer overflows or heap corruption in downstream C/C++ runtimes
(e.g. llama.cpp).
"""
from __future__ import annotations

import json
import os
import struct
from typing import Any, Dict, List, Tuple

FORMAT = "GGUF"
MAGIC = b"GGUF"
SUPPORTED_VERSIONS = (1, 2, 3)
MAX_COUNT = 1_000_000              # tensor / kv count sanity ceiling
MAX_STRING_LEN = 8 * 1024 * 1024   # 8 MiB cap per metadata string
MAX_ARRAY_LEN = 4_000_000          # cap per metadata array

# GGUF metadata value types
_VALUE_TYPES = {
    0: ("UINT8", 1, "<B"), 1: ("INT8", 1, "<b"),
    2: ("UINT16", 2, "<H"), 3: ("INT16", 2, "<h"),
    4: ("UINT32", 4, "<I"), 5: ("INT32", 4, "<i"),
    6: ("FLOAT32", 4, "<f"), 7: ("BOOL", 1, "<B"),
    8: ("STRING", None, None), 9: ("ARRAY", None, None),
    10: ("UINT64", 8, "<Q"), 11: ("INT64", 8, "<q"),
    12: ("FLOAT64", 8, "<d"),
}


class GGUFBoundaryError(Exception):
    """Raised when a declared field would read past the end of the file."""


def _report(model_name: str, verdict: str, confidence: str, attack_vector: str,
            summary: str, **details: Any) -> Dict[str, Any]:
    return {
        "model_name": model_name, "format": FORMAT, "verdict": verdict,
        "confidence": confidence, "attack_vector": attack_vector,
        "summary": summary, "technical_details": details,
    }


class _Reader:
    """Bounds-checked cursor over the GGUF byte stream."""

    def __init__(self, data: bytes, version: int) -> None:
        self.data = data
        self.pos = 0
        self.version = version

    def take(self, n: int, what: str) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise GGUFBoundaryError(
                f"{what}: need {n} bytes at offset {self.pos}, "
                f"only {len(self.data) - self.pos} remain")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u32(self, what: str) -> int:
        return struct.unpack("<I", self.take(4, what))[0]

    def u64(self, what: str) -> int:
        return struct.unpack("<Q", self.take(8, what))[0]

    def count(self, what: str) -> int:
        # v1 uses 32-bit counts; v2+ uses 64-bit
        value = self.u32(what) if self.version == 1 else self.u64(what)
        if value > MAX_COUNT:
            raise GGUFBoundaryError(f"{what}: declared count {value} exceeds "
                                    f"sanity ceiling {MAX_COUNT}")
        return value

    def string(self, what: str) -> str:
        length = self.u32(what) if self.version == 1 else self.u64(what)
        if length > MAX_STRING_LEN:
            raise GGUFBoundaryError(
                f"{what}: string length {length} exceeds cap {MAX_STRING_LEN} "
                f"(heap-corruption guard)")
        return self.take(length, what).decode("utf-8", "replace")


def _read_value(reader: _Reader, vtype: int, what: str) -> Any:
    if vtype not in _VALUE_TYPES:
        raise ValueError(f"unknown metadata value type {vtype}")
    name, size, fmt = _VALUE_TYPES[vtype]
    if name == "STRING":
        return reader.string(what)
    if name == "ARRAY":
        elem_type = reader.u32(what + " elem-type")
        if elem_type not in _VALUE_TYPES or _VALUE_TYPES[elem_type][0] == "ARRAY":
            raise ValueError(f"array with illegal element type {elem_type}")
        count = reader.u32(what + " count") if reader.version == 1 \
            else reader.u64(what + " count")
        if count > MAX_ARRAY_LEN:
            raise GGUFBoundaryError(
                f"{what}: array length {count} exceeds cap {MAX_ARRAY_LEN}")
        ename, esize, efmt = _VALUE_TYPES[elem_type]
        if ename == "STRING":
            return [reader.string(what + "[]") for _ in range(count)]
        return [struct.unpack(efmt, reader.take(esize, what + "[]"))[0]
                for _ in range(count)]
    return struct.unpack(fmt, reader.take(size, what))[0]


def scan_gguf(path: str) -> Dict[str, Any]:
    """Parse and validate a GGUF file. Returns Vigilant telemetry."""
    name = os.path.basename(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return _report(name, "SUSPICIOUS", "LOW", "NONE",
                       f"Unreadable file: {exc}", error=str(exc))

    if len(data) < 4 or data[:4] != MAGIC:
        return _report(name, "SUSPICIOUS", "HIGH", "NONE",
                       "Bad magic: not a GGUF container.",
                       magic=data[:4].hex())

    header = _Reader(data[:24], version=2)  # provisional, for fixed header
    header.pos = 4
    try:
        version = struct.unpack("<I", data[4:8])[0]
    except struct.error:
        return _report(name, "SUSPICIOUS", "MEDIUM", "NONE",
                       "Truncated header (no version field).")

    if version not in SUPPORTED_VERSIONS:
        return _report(name, "SUSPICIOUS", "MEDIUM", "NONE",
                       f"Unsupported GGUF version {version}.", version=version)

    reader = _Reader(data, version)
    reader.pos = 8
    violations: List[str] = []
    try:
        tensor_count = reader.count("tensor_count")
        kv_count = reader.count("metadata_kv_count")

        metadata_preview: Dict[str, Any] = {}
        for i in range(kv_count):
            key = reader.string(f"kv[{i}].key")
            vtype = reader.u32(f"kv[{i}].type")
            value = _read_value(reader, vtype, f"kv[{i}].value")
            if len(metadata_preview) < 16:
                metadata_preview[key] = (value if not isinstance(value, list)
                                         else f"<array len={len(value)}>")
    except GGUFBoundaryError as exc:
        return _report(name, "MALICIOUS", "HIGH", "DOS_BOMB",
                       f"GGUF boundary violation — crafted to overrun buffers "
                       f"in C/C++ loaders: {exc}",
                       version=version, violation=str(exc),
                       file_size=len(data))
    except (ValueError, struct.error) as exc:
        return _report(name, "SUSPICIOUS", "MEDIUM", "NONE",
                       f"Malformed GGUF metadata: {exc}",
                       version=version, violation=str(exc),
                       file_size=len(data))

    return _report(name, "BENIGN", "HIGH", "NONE",
                   f"Valid GGUF v{version}: {tensor_count} tensors, "
                   f"{kv_count} metadata kvs, all bounds respected.",
                   version=version, tensor_count=tensor_count,
                   metadata_kv_count=kv_count,
                   metadata_preview=metadata_preview,
                   header_bytes_consumed=reader.pos, file_size=len(data),
                   violations=violations)


if __name__ == "__main__":
    import sys
    print(json.dumps(scan_gguf(sys.argv[1]), indent=2, default=str))
