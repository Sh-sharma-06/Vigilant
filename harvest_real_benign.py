#!/usr/bin/env python3
"""
Downloads REAL small (< 20 MB) benign models across PyTorch, Safetensors, ONNX, Keras/HDF5, and GGUF
from Hugging Face Hub to test true false-positive rates (provenance='hf-production').
"""
import argparse
import os
from pathlib import Path
from huggingface_hub import HfApi, hf_hub_download

TARGET_EXTENSIONS = {
    "safetensors": (".safetensors",),
    "onnx": (".onnx",),
    "hdf5": (".h5", ".keras"),
    "gguf": (".gguf",),
    "pytorch": (".bin", ".pt", ".pth", ".pkl"),
}

SEARCH_QUERIES = {
    "safetensors": ["tiny", "mini", "bert-tiny", "resnet", "lora"],
    "onnx": ["onnx", "tiny", "mnist", "mobilenet", "squeezenet"],
    "hdf5": ["keras", "h5", "mnist", "cifar"],
    "gguf": ["gguf", "tiny", "smollm", "q2_k"],
    "pytorch": ["tiny-random", "bert-tiny", "mnist", "adapter"],
}

def harvest(out_dir: Path, per_format: int = 20, max_size_mb: float = 20.0):
    api = HfApi()
    out_dir.mkdir(parents=True, exist_ok=True)
    max_bytes = int(max_size_mb * 1024 * 1024)

    for fmt, exts in TARGET_EXTENSIONS.items():
        collected = 0
        seen_repos = set()
        print(f"[*] Harvesting up to {per_format} real {fmt.upper()} models (< {max_size_mb} MB) from Hugging Face...")
        for query in SEARCH_QUERIES[fmt]:
            if collected >= per_format:
                break
            try:
                models = api.list_models(search=query, limit=60)
            except Exception as e:
                print(f"  [!] Query {query} failed: {e}")
                continue

            for m in models:
                if collected >= per_format or m.id in seen_repos:
                    break
                seen_repos.add(m.id)
                try:
                    info = api.model_info(m.id, files_metadata=True)
                    for sib in info.siblings or []:
                        fname = sib.rfilename
                        size = getattr(sib, "size", None)
                        if any(fname.lower().endswith(ext) for ext in exts) and size and 128 < size <= max_bytes:
                            safe_repo = m.id.replace("/", "__")
                            base_name = os.path.basename(fname)
                            dest = out_dir / f"hf_benign_{fmt}_{safe_repo}__{base_name}"
                            if dest.exists():
                                collected += 1
                                break
                            local_path = hf_hub_download(repo_id=m.id, filename=fname, local_dir=str(out_dir / ".cache"))
                            os.replace(local_path, dest)
                            collected += 1
                            print(f"  [+] ({collected}/{per_format}) Downloaded {dest.name} ({size/1024:.1f} KB)")
                            break
                except Exception:
                    continue

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=Path("real_hf_benign"))
    ap.add_argument("--per-format", type=int, default=15)
    args = ap.parse_args()
    harvest(args.out_dir, args.per_format)
