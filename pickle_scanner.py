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
import zipfile
from pathlib import Path

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
}

# Opcode that actually invokes a callable during unpickling.
CALL_OPCODES = {"REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX"}

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


def _iter_pickle_streams(path: Path):
    """
    Yield (label, raw_bytes) for every pickle stream found in the file.
    Handles both raw pickle files and the zip-based format PyTorch uses
    for torch.save() with zipfile serialization (a .pt file is often a
    zip archive containing data.pkl plus tensor storage blobs).
    """
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith(".pkl") or name.endswith("/data.pkl"):
                    yield name, zf.read(name)
    else:
        yield path.name, path.read_bytes()


def _target_name(arg) -> str:
    """Normalize the operand of a GLOBAL/STACK_GLOBAL op to 'module.qualname'."""
    if isinstance(arg, tuple):
        return ".".join(str(a) for a in arg)
    return str(arg)


def scan_stream(label: str, data: bytes) -> dict:
    findings = []
    referenced_targets = []   # every module.qualname seen, in order
    recent_strings = []       # sliding window of recently-pushed string literals

    try:
        for opcode, arg, pos in pickletools.genops(data):
            name = opcode.name

            if name in STRING_PUSH_OPCODES and isinstance(arg, str):
                recent_strings.append(arg)
                if len(recent_strings) > 4:
                    recent_strings.pop(0)

            if name == "GLOBAL":
                # Old-style GLOBAL: pickletools decodes the arg itself as
                # "module qualname" (space-separated).
                target = _target_name(arg).replace(" ", ".", 1) if arg else "UNKNOWN"
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
    except Exception as e:
        return {
            "stream": label,
            "verdict": "unparseable",
            "error": str(e),
            "findings": [],
        }

    verdict = "suspicious" if findings else "clean"
    return {"stream": label, "verdict": verdict, "findings": findings}


def scan_file(path: Path) -> dict:
    if not path.exists():
        return {"file": str(path), "verdict": "error", "error": "file not found"}

    stream_results = [scan_stream(label, data) for label, data in _iter_pickle_streams(path)]

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
