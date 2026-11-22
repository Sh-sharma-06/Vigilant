import os
import json
import requests

# Tiny benign models from Hugging Face (Vision and NLP)
MODELS = [
    {
        "url": "https://huggingface.co/hf-internal-testing/tiny-random-resnet/resolve/main/pytorch_model.bin",
        "filename": "benign_vision_resnet.bin",
        "category": "vision",
        "source": "huggingface/hf-internal-testing/tiny-random-resnet"
    },
    {
        "url": "https://huggingface.co/prajjwal1/bert-tiny/resolve/main/pytorch_model.bin",
        "filename": "benign_nlp_bert.bin",
        "category": "nlp",
        "source": "huggingface/prajjwal1/bert-tiny"
    }
]

DATASET_DIR = "eval_dataset"
MANIFEST_PATH = os.path.join(DATASET_DIR, "manifest.json")

def download_file(url, dest_path):
    print(f"[*] Downloading {os.path.basename(dest_path)}...")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    with open(dest_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"[+] Saved {dest_path}")

def update_manifest():
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)
    
    # Add new models to manifest if they aren't already there
    existing_files = {sample["filename"] for sample in manifest["samples"]}
    
    for model in MODELS:
        dest_path = os.path.join(DATASET_DIR, model["filename"])
        download_file(model["url"], dest_path)
        
        if model["filename"] not in existing_files:
            manifest["samples"].append({
                "filename": model["filename"],
                "category": model["category"],
                "source": model["source"],
                "notes": "Safe, known-benign baseline model"
            })
            
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    print("[+] Updated manifest.json")

if __name__ == "__main__":
    if not os.path.exists(DATASET_DIR):
        os.makedirs(DATASET_DIR)
    update_manifest()
