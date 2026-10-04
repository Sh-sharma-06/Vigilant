import hashlib
import json
import os

MODEL_DIR = "eval_dataset"
MANIFEST_FILE = os.path.join(MODEL_DIR, "manifest.json")

def compute_sha256(filepath):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()

manifest_data = []

# Expanded to catch all downloaded formats
EXTENSIONS = (".bin", ".pt", ".pth", ".pkl", ".pickle", ".npz", ".joblib")

for root, _, files in os.walk(MODEL_DIR):
    for filename in sorted(files):
        # Only hash files that match our extensions AND start with a number (1_ to 47_)
        # This safely ignores the un-numbered duplicates from the first failed download run
        if filename.endswith(EXTENSIONS) and filename[0].isdigit():
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, MODEL_DIR)
            
            print(f"Hashing: {filename}...")
            sha256_hash = compute_sha256(full_path)
            
            manifest_data.append({
                "filename": filename,
                "relative_path": rel_path,
                "sha256": sha256_hash,
                "category": "benign",
                "source": "huggingface"
            })

with open(MANIFEST_FILE, "w") as f:
    json.dump(manifest_data, f, indent=4)

print(f"\nManifest successfully created at {MANIFEST_FILE} with {len(manifest_data)} entries.")
