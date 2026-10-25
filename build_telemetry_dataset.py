import csv
import glob
import io
import json
import os
import pickletools
import zipfile
from typing import Any, Dict, List

from inspectors.multi_format_scanner import (
    compute_entropy_profile,
    identify_format,
    scan_gguf,
    scan_hdf5,
    scan_onnx,
    scan_safetensors,
)
from container_dispatcher import check_mod_target, is_printable_text, strip_zip_encryption_bits

FEATURE_COLUMNS = [
    "mean_entropy",
    "max_entropy",
    "high_entropy_windows",
    "is_archive",
    "max_compression_ratio",
    "zip_bitflip_anomaly",
    "header_polyglot_anomaly",
    "global_opcode_count",
    "stack_global_count",
    "reduce_opcode_count",
    "custom_instantiation_hits",
    "taint_dfg_sink_hits",
    "suspicious_string_hits",
    "multiformat_ast_hits",
    "truncated_inert_flag",
]

SAFE_STANDARD_MODULES = {
    "torch", "numpy", "collections", "copy_reg", "_codecs", "__builtin__",
    "builtins", "sklearn", "joblib", "scipy", "pandas", "datetime", "pathlib"
}

def _extract_pickle_dfg_features(data: bytes) -> Dict[str, int]:
    stats = {
        "global_opcode_count": 0,
        "stack_global_count": 0,
        "reduce_opcode_count": 0,
        "custom_instantiation_hits": 0,
        "taint_dfg_sink_hits": 0,
        "suspicious_string_hits": 0,
        "truncated_inert_flag": 0,
    }
    stack: List[Dict[str, Any]] = []
    memo: Dict[Any, Dict[str, Any]] = {}
    has_exec_sink = False

    try:
        for op, arg, pos in pickletools.genops(data):
            name = op.name
            if name in ("REDUCE", "BUILD", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
                has_exec_sink = True
                stats["reduce_opcode_count"] += 1
                if name in ("INST", "OBJ", "BUILD"):
                    stats["custom_instantiation_hits"] += 1
                if len(stack) >= 2:
                    args_node = stack.pop()
                    fn_node = stack.pop()
                    is_tainted = fn_node.get("tainted", False) or args_node.get("tainted", False)
                    if is_tainted:
                        stats["taint_dfg_sink_hits"] += 1
                    stack.append({"val": f"Call({fn_node.get('val')})", "tainted": is_tainted})
                elif stack:
                    top = stack.pop()
                    if top.get("tainted", False):
                        stats["taint_dfg_sink_hits"] += 1
                    stack.append(top)

            elif name == "STOP":
                has_exec_sink = True

            elif name == "GLOBAL":
                stats["global_opcode_count"] += 1
                mod = arg if isinstance(arg, str) else arg.decode("utf-8", "ignore")
                is_mal, _ = check_mod_target(mod)
                base_mod = mod.split(".")[0].split(" ")[0]
                if base_mod not in SAFE_STANDARD_MODULES:
                    stats["custom_instantiation_hits"] += 1
                stack.append({"val": mod, "tainted": is_mal})
                if is_mal:
                    stats["taint_dfg_sink_hits"] += 1

            elif name in ("UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8", "STRING", "BINSTRING", "SHORT_BINSTRING"):
                val = arg if isinstance(arg, str) else arg.decode("utf-8", "ignore")
                tainted_str = False
                if name in ("UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8") or is_printable_text(val):
                    if val in ("eval", "exec", "subprocess", "posix_spawn", "_pickle", "cPickle", "marshal", "system", "popen", "compile_file", "weights_only"):
                        tainted_str = True
                        stats["suspicious_string_hits"] += 1
                    elif is_printable_text(val) and any(x in val for x in ("exec(", "eval(", "__import__(", "getattr(", "system(", "os.popen(", "subprocess.", "sh -c", "/bin/sh", "/bin/bash", "$(echo", "http://", "https://", ".aws", "credentials", "socket", "urllib", "requests", "webbrowser", "runpy", "pty", "ctypes", "pickle", "loads")):
                        tainted_str = True
                        stats["suspicious_string_hits"] += 1
                stack.append({"val": val, "tainted": tainted_str})

            elif name == "MEMOIZE":
                if stack:
                    memo[len(memo)] = dict(stack[-1])

            elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                if stack:
                    memo[arg] = dict(stack[-1])

            elif name in ("GET", "BINGET", "LONG_BINGET"):
                stack.append(dict(memo.get(arg, {"val": "", "tainted": False})))

            elif name == "STACK_GLOBAL":
                stats["stack_global_count"] += 1
                if len(stack) >= 2:
                    attr_node = stack.pop()
                    mod_node = stack.pop()
                    combined = f"{mod_node.get('val', '')} {attr_node.get('val', '')}"
                    is_mal, _ = check_mod_target(combined)
                    base_mod = combined.split(".")[0].split(" ")[0]
                    if base_mod not in SAFE_STANDARD_MODULES:
                        stats["custom_instantiation_hits"] += 1
                    tainted = is_mal or mod_node.get("tainted", False) or attr_node.get("tainted", False)
                    if tainted:
                        stats["taint_dfg_sink_hits"] += 1
                    stack.append({"val": combined, "tainted": tainted})

            else:
                if len(stack) > 64:
                    stack = stack[-32:]
    except Exception as e:
        err = str(e).lower()
        if "expected" in err and "bytes" in err and "but only" in err and not has_exec_sink:
            stats["truncated_inert_flag"] = 1
            stats["taint_dfg_sink_hits"] = 0
            stats["suspicious_string_hits"] = 0
            stats["custom_instantiation_hits"] = 0

    return stats

def extract_model_features(file_path: str) -> Dict[str, Any]:
    fmt = identify_format(file_path)
    ent = compute_entropy_profile(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    feats: Dict[str, Any] = {
        "mean_entropy": ent["mean_entropy"],
        "max_entropy": ent["max_entropy"],
        "high_entropy_windows": ent["high_entropy_windows"],
        "is_archive": 1 if fmt in ("ZIP", "7Z") or ext in (".zip", ".7z") else 0,
        "max_compression_ratio": 1.0,
        "zip_bitflip_anomaly": 0,
        "header_polyglot_anomaly": 0,
        "global_opcode_count": 0,
        "stack_global_count": 0,
        "reduce_opcode_count": 0,
        "custom_instantiation_hits": 0,
        "taint_dfg_sink_hits": 0,
        "suspicious_string_hits": 0,
        "multiformat_ast_hits": 0,
        "truncated_inert_flag": 0,
    }

    try:
        with open(file_path, "rb") as f:
            raw_head = f.read(5 * 1024 * 1024)
        if ext in (".pt", ".pth", ".bin", ".pkl", ".pickle") and raw_head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"%PDF", b"\x7fELF", b"MZ")):
            feats["header_polyglot_anomaly"] = 1
            feats["multiformat_ast_hits"] += 1
        if raw_head.startswith(b"7z\xbc\xaf'\x1c") or ext == ".7z":
            feats["is_archive"] = 1
            feats["multiformat_ast_hits"] += 1
    except Exception:
        pass

    if fmt == "HDF5":
        res = scan_hdf5(file_path)
        feats["multiformat_ast_hits"] += len(res["reasons"])
    elif fmt == "ONNX":
        res = scan_onnx(file_path)
        feats["multiformat_ast_hits"] += len(res["reasons"])
    elif fmt == "GGUF":
        res = scan_gguf(file_path)
        feats["multiformat_ast_hits"] += len(res["reasons"])
    elif fmt == "SAFETENSORS":
        res = scan_safetensors(file_path)
        feats["multiformat_ast_hits"] += len(res["reasons"])

    if ext == ".zip" and not zipfile.is_zipfile(file_path):
        feats["zip_bitflip_anomaly"] = 1
        feats["multiformat_ast_hits"] += 1
        try:
            with open(file_path, "rb") as rf:
                p_stats = _extract_pickle_dfg_features(rf.read(5 * 1024 * 1024))
                for k, v in p_stats.items():
                    feats[k] += v
        except Exception:
            pass
    elif zipfile.is_zipfile(file_path):
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                for info in z.infolist():
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > feats["max_compression_ratio"]:
                            feats["max_compression_ratio"] = round(ratio, 2)
                for name in z.namelist():
                    if name.endswith("/"):
                        continue
                    try:
                        member_bytes = z.read(name)
                    except RuntimeError as re_err:
                        if "encrypted" in str(re_err).lower() or "password" in str(re_err).lower():
                            with open(file_path, "rb") as rf:
                                stripped = strip_zip_encryption_bits(rf.read())
                            try:
                                with zipfile.ZipFile(io.BytesIO(stripped), "r") as sz:
                                    member_bytes = sz.read(name)
                                feats["zip_bitflip_anomaly"] = 1
                            except Exception:
                                continue
                        else:
                            feats["zip_bitflip_anomaly"] = 1
                            continue
                    p_stats = _extract_pickle_dfg_features(member_bytes)
                    for k, v in p_stats.items():
                        feats[k] += v
        except Exception:
            feats["zip_bitflip_anomaly"] = 1
            feats["multiformat_ast_hits"] += 1
            try:
                with open(file_path, "rb") as rf:
                    p_stats = _extract_pickle_dfg_features(rf.read(5 * 1024 * 1024))
                    for k, v in p_stats.items():
                        feats[k] += v
            except Exception:
                pass
    elif fmt in ("PICKLE", "UNKNOWN"):
        try:
            with open(file_path, "rb") as f:
                raw_data = f.read(5 * 1024 * 1024)
            p_stats = _extract_pickle_dfg_features(raw_data)
            for k, v in p_stats.items():
                feats[k] += v
        except Exception:
            pass

    return feats

def main():
    dirs = [
        "/home/sandesh/vigilant-eval-triage/eval_dataset",
        "/home/sandesh/vigilant-eval-triage/eval_dataset_multiformat",
    ]
    files = []
    for d in dirs:
        if os.path.exists(d):
            files.extend(sorted(glob.glob(os.path.join(d, "*"))))

    rows = []
    print(f"[*] Extracting 15-dimensional size-invariant DFG & AST vectors from {len(files)} files...")
    for path in files:
        if os.path.isdir(path) or os.path.basename(path) == "manifest.json":
            continue
        fname = os.path.basename(path)
        label = 1 if any(fname.startswith(p) for p in ("malicious", "bad_", "pytorch_magic", "sys_module")) else 0
        feats = extract_model_features(path)
        row = {"model_name": fname, "format": identify_format(path), "label": label}
        row.update(feats)
        rows.append(row)

    out_csv = "/home/sandesh/vigilant-eval-triage/telemetry_dataset.csv"
    fieldnames = ["model_name", "format", "label"] + FEATURE_COLUMNS
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    out_json = "/home/sandesh/vigilant-eval-triage/telemetry_dataset.json"
    with open(out_json, "w") as f:
        json.dump(rows, f, indent=2)

    print(f"[+] Saved {len(rows)} telemetry records to {out_csv} and {out_json}")

if __name__ == "__main__":
    main()
