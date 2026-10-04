import os
import requests
from urllib.parse import urlparse

os.makedirs("eval_dataset", exist_ok=True)

with open("model_links.txt", "r") as f:
    urls = [line.strip() for line in f if line.strip()]

print(f"Total models to download: {len(urls)}")

for i, url in enumerate(urls, 1):
    # Fix the double https typo from link 46
    if url.startswith("https:https://"):
        url = url.replace("https:https://", "https://")

    clean_url = url.split("?download=true")[0]
    original_filename = os.path.basename(urlparse(clean_url).path)
    
    if not original_filename or original_filename == "/":
        original_filename = "model.bin"
        
    # Prepend the loop index to guarantee every file is uniquely named
    filename = f"{i}_{original_filename}"
    filepath = os.path.join("eval_dataset", filename)
    
    if os.path.exists(filepath):
        print(f"[{i}/{len(urls)}] Skipping (already exists): {filename}")
        continue

    print(f"[{i}/{len(urls)}] Downloading: {filename}...")
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        
        with open(filepath, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
    except Exception as e:
        print(f"[{i}/{len(urls)}] Failed: {url} -> {e}")

print("\nAll downloads finished.")
