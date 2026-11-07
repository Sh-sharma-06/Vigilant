#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import time

sys.path.insert(0, "inspectors")
from keras_scanner import scan_keras_v3, classify_zip

FORMAT_EXT_MAP = {
    ".h5": "HDF5", ".hdf5": "HDF5", ".keras": "KERAS",
    ".pkl": "PICKLE", ".pt": "PICKLE", ".bin": "PICKLE",
    ".onnx": "ONNX", ".safetensors": "SAFETENSORS", ".gguf": "GGUF",
    ".zip": "ZIP", ".7z": "7Z",
}

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def verdict_to_confidence(verdict):
    return {"CLEAN": "HIGH", "SUSPICIOUS": "MEDIUM", "MALICIOUS": "HIGH"}.get(verdict, "LOW")

def map_verdict(v):
    return {"CLEAN": "BENIGN", "SUSPICIOUS": "SUSPICIOUS", "MALICIOUS": "MALICIOUS"}.get(v, "ERROR")

def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "eval_dataset"
    teammate = sys.argv[2] if len(sys.argv) > 2 else "Shreya"
    run_num = sys.argv[3] if len(sys.argv) > 3 else "2"
    out_path = f"{teammate}{run_num}.jsonl"

    exts = (".keras", ".zip")
    files = []
    for root, dirs, names in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d != ".cache"]
        for name in names:
            if name.lower().endswith(exts):
                files.append(os.path.join(root, name))

    print(f"[*] Found {len(files)} .keras/.zip files under {target_dir}")

    with open(out_path, "w") as out_f:
        for i, path in enumerate(files, 1):
            print(f"[{i}/{len(files)}] Scanning {path} ...")
            sample_id = sha256_of(path)
            size_bytes = os.path.getsize(path)
            ext = os.path.splitext(path)[1].lower()
            start = time.time()

            try:
                if ext == ".keras":
                    result = scan_keras_v3(path)
                    fmt = "KERAS"
                else:
                    import zipfile, tempfile
                    fmt = "ZIP"
                    with zipfile.ZipFile(path) as zf:
                        nested_keras = [n for n in zf.namelist() if n.endswith(".keras")]
                    if nested_keras:
                        worst_verdict = "CLEAN"
                        all_findings = []
                        rank = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
                        with zipfile.ZipFile(path) as zf:
                            for member in nested_keras:
                                with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as tmp:
                                    tmp.write(zf.read(member))
                                    tmp_path = tmp.name
                                try:
                                    sub_result = scan_keras_v3(tmp_path)
                                    sub_v = sub_result.get("verdict", "ERROR")
                                    if rank.get(sub_v, -1) > rank.get(worst_verdict, -1):
                                        worst_verdict = sub_v
                                    all_findings.append({"member": member, "verdict": sub_v, "reason": sub_result.get("reason", "")})
                                finally:
                                    os.unlink(tmp_path)
                        result = {"verdict": worst_verdict, "findings": all_findings,
                                  "reason": f"{len(nested_keras)} nested .keras file(s) scanned; worst verdict: {worst_verdict}"}
                    else:
                        result = {"verdict": "ERROR", "reason": "no .keras members found inside zip"}
                elapsed = time.time() - start

                verdict_raw = result.get("verdict", "ERROR") if isinstance(result, dict) else "ERROR"
                record = {
                    "sample_id": sample_id,
                    "model_name": os.path.basename(path),
                    "format": fmt,
                    "source_run": f"{teammate}_run{run_num}",
                    "uploaded_by": teammate,
                    "git_commit": "local-uncommitted-keras-scanner",
                    "expected": "UNLABELED",
                    "verdict": map_verdict(verdict_raw),
                    "confidence": verdict_to_confidence(verdict_raw),
                    "latency_s": round(elapsed, 4),
                    "latency_ms": round(elapsed * 1000, 2),
                    "summary": result.get("reason", "") if isinstance(result, dict) else str(result),
                    "error": None,
                    "features": {
                        "total_size_bytes": size_bytes,
                        "raw_verdict": verdict_raw,
                        "findings": result.get("findings", []) if isinstance(result, dict) else []
                    }
                }
            except Exception as e:
                elapsed = time.time() - start
                record = {
                    "sample_id": sample_id,
                    "model_name": os.path.basename(path),
                    "format": FORMAT_EXT_MAP.get(ext, "ZIP"),
                    "source_run": f"{teammate}_run{run_num}",
                    "uploaded_by": teammate,
                    "git_commit": "local-uncommitted-keras-scanner",
                    "expected": "UNLABELED",
                    "verdict": "ERROR",
                    "confidence": "LOW",
                    "latency_s": round(elapsed, 4),
                    "latency_ms": round(elapsed * 1000, 2),
                    "summary": str(e),
                    "error": str(e),
                    "features": {"total_size_bytes": size_bytes}
                }

            out_f.write(json.dumps(record) + "\n")
            out_f.flush()
            print(f"  -> {record['verdict']} ({record['summary'][:80]})")

    print(f"\n[+] Wrote {len(files)} records to {out_path}")

if __name__ == "__main__":
    main()
