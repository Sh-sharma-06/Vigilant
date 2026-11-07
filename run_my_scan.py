#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

FORMAT_EXT_MAP = {
    ".h5": "HDF5",
    ".hdf5": "HDF5",
    ".keras": "KERAS",
    ".pkl": "PICKLE",
    ".pt": "PICKLE",
    ".bin": "PICKLE",
    ".onnx": "ONNX",
    ".safetensors": "SAFETENSORS",
    ".gguf": "GGUF",
    ".zip": "ZIP",
    ".7z": "7Z",
}

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def guess_format(path):
    ext = os.path.splitext(path)[1].lower()
    return FORMAT_EXT_MAP.get(ext, "PICKLE")

def run_dispatcher(path, dispatcher_path, timeout=120):
    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, dispatcher_path, path],
            capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start
        if result.returncode != 0:
            return None, elapsed, result.stderr.strip()[:2000]
        data = None
        decoder = json.JSONDecoder()
        search_from = 0
        while True:
            brace_idx = result.stdout.find("{", search_from)
            if brace_idx == -1:
                break
            try:
                data, _ = decoder.raw_decode(result.stdout[brace_idx:])
                break
            except (ValueError, json.JSONDecodeError):
                search_from = brace_idx + 1
        if data is None:
            return None, elapsed, f"non-JSON output: {result.stdout[:500]}"
        return data, elapsed, None
    except subprocess.TimeoutExpired:
        return None, timeout, "TIMEOUT"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--teammate", required=True)
    ap.add_argument("--run-num", required=True)
    ap.add_argument("--dispatcher", default="model_dispatcher.py")
    ap.add_argument("--git-commit", default="unknown")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    out_path = args.out or f"{args.teammate}{args.run_num}.jsonl"
    exts = tuple(FORMAT_EXT_MAP.keys())

    files = []
    for root, dirs, names in os.walk(args.dir):
        dirs[:] = [d for d in dirs if d != ".cache"]
        for name in names:
            if name.lower().endswith(exts):
                files.append(os.path.join(root, name))

    print(f"[*] Found {len(files)} candidate files under {args.dir}")

    with open(out_path, "w") as out_f:
        for i, path in enumerate(files, 1):
            print(f"[{i}/{len(files)}] Scanning {path} ...")
            sample_id = sha256_of(path)
            size_bytes = os.path.getsize(path)
            data, elapsed, err = run_dispatcher(path, args.dispatcher)

            if data is None:
                record = {
                    "sample_id": sample_id,
                    "model_name": os.path.basename(path),
                    "format": guess_format(path),
                    "source_run": f"{args.teammate}_run{args.run_num}",
                    "uploaded_by": args.teammate,
                    "git_commit": args.git_commit,
                    "expected": "UNLABELED",
                    "verdict": "TIMEOUT" if err == "TIMEOUT" else "ERROR",
                    "confidence": "LOW",
                    "latency_s": round(elapsed, 4),
                    "latency_ms": round(elapsed * 1000, 2),
                    "summary": err or "scan failed",
                    "error": err,
                    "features": {"total_size_bytes": size_bytes}
                }
            else:
                verdict = data.get("verdict", "ERROR")
                record = {
                    "sample_id": sample_id,
                    "model_name": data.get("model_name", os.path.basename(path)),
                    "format": data.get("format", guess_format(path)),
                    "source_run": f"{args.teammate}_run{args.run_num}",
                    "uploaded_by": args.teammate,
                    "git_commit": args.git_commit,
                    "expected": "UNLABELED",
                    "verdict": verdict,
                    "confidence": data.get("confidence", "LOW"),
                    "latency_s": round(elapsed, 4),
                    "latency_ms": round(elapsed * 1000, 2),
                    "summary": data.get("summary", ""),
                    "error": None,
                    "features": {
                        "total_size_bytes": size_bytes,
                        **(data.get("technical_details", {}) or {})
                    }
                }

            out_f.write(json.dumps(record) + "\n")
            out_f.flush()

    print(f"[+] Wrote {len(files)} records to {out_path}")

if __name__ == "__main__":
    main()
