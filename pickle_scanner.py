#!/usr/bin/env python3
"""
pickle_scanner.py — Static allowlist-based scanner for PyTorch pickle files.

Reads the pickle opcode stream WITHOUT executing it (pickletools.genops is
safe on untrusted input — it never reconstructs objects, only reads
instructions). Flags any GLOBAL / STACK_GLOBAL opcode that references a
module.callable pair NOT in the allowlist below, and any REDUCE opcode
(a call being made during unpickling) whose target wasn't allowlisted.

Usage:
    python3 pickle_scanner.py path/to/model.pt
    python3 pickle_scanner.py path/to/model.pt --json report.json
"""

import argparse
import json
import pickletools
import sys
import io
import zipfile
import zlib
from pathlib import Path

# Archive limits are checked from the central directory before any member is
# decompressed. They keep a crafted .pt/zip file from consuming unbounded RAM
# or CPU while the scanner is looking for data.pkl.
MAX_ZIP_MEMBERS = 10_000
MAX_ZIP_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 1_000
MAX_PICKLE_STREAM_BYTES = 64 * 1024 * 1024

# ---------------------------------------------------------------------------
# ALLOWLIST
# Format: {"module.qualname", ...}
# This is intentionally small and strict — it's meant to grow only when a
# real, understood, safe reconstructor is missing, never to "make a scan pass".
# ---------------------------------------------------------------------------
ALLOWLIST = {
    # core Python / collections used constantly in state_dicts
    "collections.OrderedDict",
    "builtins.dict",
    "builtins.list",
    "builtins.tuple",
    "builtins.set",
    "builtins.frozenset",
    "builtins.complex",
    "builtins.bytearray",
    # Python 2 module alias retained in older torch checkpoints.
    "__builtin__.set",

    # numpy scalar / array reconstruction (common in older checkpoints)
    "numpy.core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    "numpy.ndarray",
    "numpy.dtype",

    # torch tensor / storage reconstruction — the legitimate payload of
    # almost every real .pt/.pth checkpoint
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_tensor",
    "torch._utils._rebuild_parameter",
    "torch._utils._rebuild_sparse_tensor",
    "torch.Tensor",
    "torch.Size",
    "torch.storage._load_from_bytes",
    "torch.FloatStorage",
    "torch.DoubleStorage",
    "torch.HalfStorage",
    "torch.LongStorage",
    "torch.IntStorage",
    "torch.ShortStorage",
    "torch.CharStorage",
    "torch.ByteStorage",
    "torch.BoolStorage",

    # Standard torch.nn building blocks. These are concrete, reviewed module
    # classes rather than a broad torch.nn wildcard, so custom model classes
    # still require review.
    "torch.nn.parameter.Parameter",
    "torch.nn.modules.module.Module",
    "torch.nn.modules.container.Sequential",
    "torch.nn.modules.container.ModuleList",
    "torch.nn.modules.container.ModuleDict",
    "torch.nn.modules.linear.Linear",
    "torch.nn.modules.linear.Identity",
    "torch.nn.modules.conv.Conv1d",
    "torch.nn.modules.conv.Conv2d",
    "torch.nn.modules.conv.Conv3d",
    "torch.nn.modules.activation.ReLU",
    "torch.nn.modules.activation.GELU",
    "torch.nn.modules.activation.Sigmoid",
    "torch.nn.modules.activation.Softmax",
    "torch.nn.modules.activation.Tanh",
    "torch.nn.modules.dropout.Dropout",
    "torch.nn.modules.normalization.LayerNorm",
    "torch.nn.modules.batchnorm.BatchNorm1d",
    "torch.nn.modules.batchnorm.BatchNorm2d",
    "torch.nn.modules.batchnorm.BatchNorm3d",
    "torch.nn.modules.pooling.MaxPool1d",
    "torch.nn.modules.pooling.MaxPool2d",
    "torch.nn.modules.pooling.MaxPool3d",
    "torch.nn.modules.pooling.AdaptiveAvgPool1d",
    "torch.nn.modules.pooling.AdaptiveAvgPool2d",
    "torch.nn.modules.pooling.AdaptiveAvgPool3d",
    "torch.nn.modules.sparse.Embedding",
    "torch.nn.modules.loss.CrossEntropyLoss",
}

# Opcodes that instantiate or invoke a callable during unpickling. BUILD only
# applies state to an already-created object and is not itself a call.
CALL_OPCODES = {"REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ"}

# Opcodes that push a string literal onto the pickle VM stack. STACK_GLOBAL
# (protocol >= 4, the default in modern pickle/torch.save) doesn't carry its
# module/name as an immediate opcode argument the way old-style GLOBAL does —
# the module and qualname are pushed as two separate string ops just before
# it. To recover the target name we have to track the last two string pushes
# ourselves, the same way real scanners (e.g. picklescan) do.
STRING_PUSH_OPCODES = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING",
}


def _is_pickle_magic(head: bytes) -> bool:
    """Protocol 2-5 pickles start with 0x80 followed by the protocol number."""
    return len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5


def _parses_cleanly(data: bytes) -> bool:
    """True if `data` is a well-formed pickle (opcodes only, nothing executed)."""
    try:
        for _ in pickletools.genops(io.BytesIO(data)):
            pass
        return True
    except Exception:
        return False


def _read_member_raw(path: Path, info, head=None) -> bytes:
    """Read a zip member straight from its LOCAL header, ignoring the central
    directory (name, flags) -- which is what PyTorch's loader effectively does.
    Scanners that trust the central directory can be fooled by a mismatch."""
    with open(path, "rb") as fh:
        fh.seek(info.header_offset)
        hdr = fh.read(30)
        if hdr[:4] != b"PK\x03\x04":
            raise ValueError("bad local file header")
        method = int.from_bytes(hdr[8:10], "little")
        name_len = int.from_bytes(hdr[26:28], "little")
        extra_len = int.from_bytes(hdr[28:30], "little")
        fh.seek(info.header_offset + 30 + name_len + extra_len)
        raw = fh.read(info.compress_size)
    if method == 0:
        data = raw
    elif method == 8:
        data = zlib.decompressobj(-15).decompress(raw, MAX_PICKLE_STREAM_BYTES + 1)
    else:
        raise ValueError(f"unsupported compression method {method}")
    if len(data) > MAX_PICKLE_STREAM_BYTES:
        raise ValueError("member exceeds size limit once decompressed")
    return data[:head] if head else data


def _read_member(zf, path: Path, info, head=None) -> bytes:
    """Read a member. Some archives set the encrypted (0x1), patched-data (0x20)
    or strong-encryption (0x40) flag on an UNencrypted member, or give the member
    a different name in the central directory than in its local header. Python's
    zipfile refuses those but PyTorch does not, so a payload would hide from a
    scanner that gives up. Clear the flags, and if zipfile still refuses, read the
    raw bytes ourselves. A truly encrypted member fails to decompress -> unreadable."""
    info.flag_bits &= ~0x61
    try:
        with zf.open(info) as fh:
            return fh.read(head) if head else fh.read()
    except (RuntimeError, NotImplementedError, zlib.error, EOFError, zipfile.BadZipFile):
        return _read_member_raw(path, info, head)


def _iter_pickle_streams(path: Path):
    """
    Yield (label, raw_bytes) for every pickle stream found in the file.
    Handles both raw pickle files and the zip-based format PyTorch uses
    for torch.save() with zipfile serialization (a .pt file is often a
    zip archive containing data.pkl plus tensor storage blobs).
    """
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            members = zf.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                raise ValueError(f"unsafe zip archive: {len(members)} members exceeds limit")

            total_uncompressed = sum(info.file_size for info in members)
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise ValueError(
                    "unsafe zip archive: declared uncompressed size exceeds limit"
                )

            for info in members:
                # A zero-sized compressed member is harmless. A non-empty
                # member with zero compressed bytes is malformed/suspicious.
                if info.file_size and not info.compress_size:
                    raise ValueError(f"unsafe zip archive: invalid compressed size for {info.filename}")
                if info.compress_size and info.file_size / info.compress_size > MAX_ZIP_COMPRESSION_RATIO:
                    raise ValueError(f"unsafe zip archive: compression ratio exceeds limit for {info.filename}")

                is_pkl_name = info.filename.endswith(".pkl")
                if info.file_size > MAX_PICKLE_STREAM_BYTES:
                    if is_pkl_name:
                        raise ValueError(f"unsafe zip archive: pickle stream exceeds limit for {info.filename}")
                    continue                      # big blobs (tensor data) are not pickles
                # A pickle can hide under any member name (e.g. data.txt), so peek at the
                # first two bytes of every other member and scan the ones that look like one.
                if not is_pkl_name:
                    try:
                        if not _is_pickle_magic(_read_member(zf, path, info, head=2)):
                            continue
                    except Exception:
                        continue
                try:
                    data = _read_member(zf, path, info)
                except Exception as exc:
                    if is_pkl_name:
                        raise ValueError(f"unreadable pickle member {info.filename}: {type(exc).__name__}: {exc}")
                    continue
                if not is_pkl_name and not _parses_cleanly(data):
                    continue                      # starts with 0x80 by chance, e.g. tensor bytes
                yield info.filename, data
    else:
        if path.stat().st_size > MAX_PICKLE_STREAM_BYTES:
            raise ValueError("unsafe pickle stream: file size exceeds limit")
        yield path.name, path.read_bytes()


# Pickle protocol 2 (and lower) writes some stdlib module names using their
# old Python-2 aliases for cross-version compatibility -- e.g. a plain
# Python `set` is emitted as GLOBAL '__builtin__ set', not 'builtins set',
# even when written by Python 3. Without normalizing this, nn.Module's own
# self._non_persistent_buffers_set (a real, harmless Python set that every
# torch.save(model, ...) full-model checkpoint contains) shows up as a
# non-allowlisted target and false-positives the scan. This is a distinct
# bug from the allowlist-scope decision above -- confirmed against the
# actual benign_model.pt opcode stream, not assumed.
_MODULE_ALIASES = {
    "__builtin__": "builtins",
}


def _target_name(arg) -> str:
    """Normalize the operand of a GLOBAL/STACK_GLOBAL op to 'module.qualname'."""
    if isinstance(arg, tuple):
        return ".".join(str(a) for a in arg)
    return str(arg)


def _normalize_target(target: str) -> str:
    """Apply legacy module-alias normalization to a fully-formed
    'module.qualname' string (called AFTER any space->dot conversion)."""
    module, _, rest = target.partition(".")
    module = _MODULE_ALIASES.get(module, module)
    return f"{module}.{rest}" if rest else module


def _scan_one_pickle(buf, findings: list) -> None:
    """Scan ONE pickle (up to its STOP opcode) from a binary buffer."""
    referenced_targets = []   # every module.qualname seen, in order
    recent_strings = []       # sliding window of recently-pushed string literals
    memo = {}                 # memo index -> string stored there (or None)
    memo_next = 0             # next index used by MEMOIZE (protocol 4+)
    last_str = None           # string on top of stack, if the top is a string

    for opcode, arg, pos in pickletools.genops(buf):
        name = opcode.name

        if name in STRING_PUSH_OPCODES and isinstance(arg, str):
            recent_strings.append(arg)
            if len(recent_strings) > 4:
                recent_strings.pop(0)
            last_str = arg
        elif name == "MEMOIZE":
            memo[memo_next] = last_str
            memo_next += 1
        elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
            memo[arg] = last_str
        elif name in ("GET", "BINGET", "LONG_BINGET"):
            last_str = memo.get(arg)
            if last_str is not None:
                recent_strings.append(last_str)
                if len(recent_strings) > 4:
                    recent_strings.pop(0)
        else:
            last_str = None

        if name in ("GLOBAL", "INST"):
            # INST = GLOBAL + immediate call, same "module name" operand.
            # Old-style GLOBAL: pickletools decodes the arg itself as
            # "module qualname" (space-separated).
            target = _target_name(arg).replace(" ", ".", 1) if arg else "UNKNOWN"
            target = _normalize_target(target)
            referenced_targets.append(target)
            if target not in ALLOWLIST:
                findings.append({
                    "position": pos, "opcode": name, "target": target,
                    "reason": "target not in allowlist",
                })

        elif name == "STACK_GLOBAL":
            # Reconstruct from the last two string pushes on the stack.
            if len(recent_strings) >= 2:
                module, qualname = recent_strings[-2], recent_strings[-1]
                target = f"{module}.{qualname}"
            else:
                target = "UNKNOWN"
            target = _normalize_target(target)
            referenced_targets.append(target)
            if target not in ALLOWLIST:
                findings.append({
                    "position": pos, "opcode": name, "target": target,
                    "reason": "target not in allowlist",
                })

        elif name in CALL_OPCODES:
            # A call/build is happening — if the most recently referenced
            # global wasn't allowlisted, this is where it actually bites.
            last_target = referenced_targets[-1] if referenced_targets else None
            if last_target is not None and last_target not in ALLOWLIST:
                findings.append({
                    "position": pos,
                    "opcode": name,
                    "target": last_target,
                    "reason": "call/build on non-allowlisted target",
                })


def scan_stream(label: str, data: bytes) -> dict:
    """Scan every pickle in `data`. Payloads can be appended after a harmless
    first pickle (one real sample does exactly that), so we keep going until
    the bytes run out."""
    findings: list = []
    buf = io.BytesIO(data)
    streams = 0
    try:
        while buf.tell() < len(data):
            _scan_one_pickle(buf, findings)
            streams += 1
            if not data[buf.tell():].strip(b"\x00\r\n \t"):
                break
    except Exception as e:
        if streams > 0:
            # Bytes after a complete pickle that do not parse (e.g. the raw tensor
            # data of legacy torch.save files). Keep what the earlier pickles showed.
            return {"stream": label, "verdict": "suspicious" if findings else "clean",
                    "findings": findings, "note": f"trailing data not parsed: {e}"}
        # Findings seen BEFORE the parse error still matter: pickle executes
        # opcodes in order, so a payload can run before the bad bytes.
        return {
            "stream": label,
            "verdict": "suspicious" if findings else "unparseable",
            "error": str(e),
            "findings": findings,
        }

    verdict = "suspicious" if findings else "clean"
    return {"stream": label, "verdict": verdict, "findings": findings}


def scan_file(path: Path) -> dict:
    if not path.exists():
        return {"file": str(path), "verdict": "error", "error": "file not found"}

    try:
        stream_results = [scan_stream(label, data) for label, data in _iter_pickle_streams(path)]
    except Exception as exc:   # any failure = error (the policy treats that as suspicious)
        return {"file": str(path), "verdict": "error", "error": f"{type(exc).__name__}: {exc}"}

    if not stream_results:
        return {"file": str(path), "verdict": "error", "error": "no pickle stream found in file"}

    if any(r["verdict"] == "suspicious" for r in stream_results):
        overall = "suspicious"
    elif any(r["verdict"] == "unparseable" for r in stream_results):
        overall = "unparseable"
    else:
        overall = "clean"

    return {"file": str(path), "verdict": overall, "streams": stream_results}


def main():
    parser = argparse.ArgumentParser(description="Static allowlist scanner for PyTorch pickle files.")
    parser.add_argument("target", help="Path to a .pkl/.pt/.pth file")
    parser.add_argument("--json", metavar="OUT", help="Write full JSON report to this path")
    args = parser.parse_args()

    result = scan_file(Path(args.target))

    print(f"\nFile:    {result['file']}")
    print(f"Verdict: {result['verdict'].upper()}")

    if result["verdict"] == "suspicious":
        for stream in result.get("streams", []):
            for f in stream["findings"]:
                print(f"  [!] stream={stream['stream']} pos={f['position']} "
                      f"{f['opcode']} -> {f['target']}  ({f['reason']})")
    elif result["verdict"] == "error":
        print(f"  error: {result.get('error')}")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2))
        print(f"\nFull report written to {args.json}")

    sys.exit(1 if result["verdict"] not in ("clean",) else 0)


if __name__ == "__main__":
    main()