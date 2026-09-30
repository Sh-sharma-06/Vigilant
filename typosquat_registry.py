import difflib
import hashlib
import json
from pathlib import Path
from pydantic import BaseModel

class RegistryEntry(BaseModel):
    name: str
    expected_hash: str
    author: str

class TyposquatRegistry:
    """
    SECURITY NOTICE: This registry is itself a poisonable attack surface. 
    It relies on local data integrity and is separate from the model's actual 
    execution behavior or accuracy benchmarking. If an attacker gains write access 
    to this registry, they can whitelist malicious hashes.
    """
    def __init__(self):
        # In a production environment, this would be a signed JSON or SQLite DB.
        self.known_models: dict[str, RegistryEntry] = {
            "gemma:2b": RegistryEntry(name="gemma:2b", expected_hash="b50d6c999e592ae4f79acae23b4feaefbdfceaa7cd366df2610e3072c052a160", author="google"),
            "llama3:8b": RegistryEntry(name="llama3:8b", expected_hash="a1b2c3d4...", author="meta"),
            "bert-base-uncased": RegistryEntry(name="bert-base-uncased", expected_hash="3f4a5b6c...", author="google"),
            "benign_model": RegistryEntry(
                name="benign_model",
                expected_hash="89968f5d5b2fc93cd4d4268e00834e192118a50fdc31b541f60618de7296058e",
                author="Vigilant repository fixture",
            ),
            "canary_model": RegistryEntry(
    name="canary_model",
    expected_hash="ae45c0652eb491283c610b7d42c9dfbcd4bc32b5b25aa1989ef7c4256313bbb7",
    author="Vigilant repository fixture",
),
        }
        
    @staticmethod
    def _sha256(filepath: str | Path) -> str:
        """Hash a candidate model without loading it into memory or executing it."""
        digest = hashlib.sha256()
        with Path(filepath).open("rb") as model_file:
            for block in iter(lambda: model_file.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def check_model(self, target_name: str, filepath: str | Path | None = None, threshold: float = 0.7) -> dict:
        """Checks exact names and hashes before considering near-miss typosquats."""
        if target_name in self.known_models:
            if filepath is None:
                return {
                    "status": "REJECT_UNVERIFIED",
                    "alert": "A registered name is not trusted without a model file hash.",
                }
            try:
                actual_hash = self._sha256(filepath)
            except OSError as e:
                return {
                    "status": "REJECT_UNVERIFIED",
                    "alert": f"Could not hash model file: {e}",
                }

            expected_hash = self.known_models[target_name].expected_hash
            if actual_hash != expected_hash:
                return {
                    "status": "REJECT_HASH_MISMATCH",
                    "alert": "Registered model name does not match its expected SHA-256 hash.",
                    "expected_hash": expected_hash,
                    "actual_hash": actual_hash,
                }
            return {
                "status": "safe", 
                "match": self.known_models[target_name].model_dump(),
                "sha256": actual_hash,
            }
            
        # difflib uses Gestalt pattern matching (similar to Levenshtein distance)
        known_names = list(self.known_models.keys())
        matches = difflib.get_close_matches(target_name, known_names, n=1, cutoff=threshold)
        
        if matches:
            return {
                "status": "REJECT_TYPOSQUAT",
                "alert": f"Potential typosquat detected. Did you mean '{matches[0]}'?",
                "suggested_safe_alternative": self.known_models[matches[0]].model_dump()
            }
            
        return {
            "status": "REJECT_UNVERIFIED",
            "alert": "Model is not present in the trusted registry.",
        }

if __name__ == "__main__":
    registry = TyposquatRegistry()
    print("[!] SECURITY WARNING: This registry is a poisonable attack surface.\n")
    
    test_cases = [
        "gemma:2b",         # Exact match
        "gema:2b",          # Typosquat (missing 'm')
        "gemma:2c",         # Typosquat (wrong version letter)
        "llama3:8b",        # Exact match
        "llama2:8b",        # Typosquat (wrong version number)
        "unknown_model:1b"  # No match
    ]
    
    for test in test_cases:
        print(f"[*] Checking: '{test}'")
        print(json.dumps(registry.check_model(test), indent=2))
        print("-" * 40)
