import hashlib
import json
import os
import difflib

class TyposquatRegistry:
    def __init__(self):
        self.known_safe_models = self.load_safe_models()

    def load_safe_models(self):
        """Dynamically load trusted models and their SHA-256 hashes from the manifest."""
        manifest_path = "eval_dataset/manifest.json"
        safe_models = {}
        
        if os.path.exists(manifest_path):
            with open(manifest_path, "r") as f:
                data = json.load(f)
                for entry in data:
                    safe_models[entry["filename"]] = entry["sha256"]
                    
        return safe_models

    def compute_sha256(self, filepath):
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(8192 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    def check_typosquat(self, filename, threshold=0.8):
        """
        Uses Gestalt pattern matching to detect near-miss typosquats against the registry.
        """
        for safe_name in self.known_safe_models.keys():
            similarity = difflib.SequenceMatcher(None, filename, safe_name).ratio()
            if similarity > threshold and filename != safe_name:
                return f"WARNING: '{filename}' is suspiciously similar to trusted model '{safe_name}' (Similarity: {similarity:.2f})."
        return None

    def check_model(self, model_name, filepath):
        """
        Validates model integrity. Returns a dictionary status for the pipeline orchestrator.
        """
        filepath = str(filepath)
        filename = os.path.basename(filepath)
        print(f"[Registry] Checking '{filename}'...")
        
        # 1. Gestalt Pattern Matching for Typosquats
        typosquat_warning = self.check_typosquat(filename)
        if typosquat_warning:
            print(f"[Registry] {typosquat_warning}")
        
        # 2. Unknown artifact check (Fail-closed)
        if filename not in self.known_safe_models:
            reason = f"'{filename}' is not in the trusted registry."
            print(f"[Registry] REJECTED: {reason}")
            return {"status": "rejected", "reason": reason}
            
        # 3. Hash mismatch check (Fail-closed)
        actual_hash = self.compute_sha256(filepath)
        expected_hash = self.known_safe_models[filename]
        
        if actual_hash != expected_hash:
            reason = f"Hash mismatch for '{filename}'!"
            print(f"[Registry] REJECTED: {reason}")
            return {"status": "rejected", "reason": reason}
            
        print(f"[Registry] PASS: '{filename}' verified successfully.")
        return {"status": "safe"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        registry = TyposquatRegistry()
        name = os.path.splitext(os.path.basename(sys.argv[1]))[0]
        print(registry.check_model(name, sys.argv[1]))
