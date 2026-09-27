import json
import difflib
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
            "bert-base-uncased": RegistryEntry(name="bert-base-uncased", expected_hash="3f4a5b6c...", author="google")
        }
        
    def check_model(self, target_name: str, threshold: float = 0.7) -> dict:
        """Checks for exact matches, then flags near-miss typosquats."""
        if target_name in self.known_models:
            return {
                "status": "safe", 
                "match": self.known_models[target_name].model_dump()
            }
            
        # difflib uses Gestalt pattern matching (similar to Levenshtein distance)
        known_names = list(self.known_models.keys())
        matches = difflib.get_close_matches(target_name, known_names, n=1, cutoff=threshold)
        
        if matches:
            return {
                "status": "warning_typosquat",
                "alert": f"Potential typosquat detected. Did you mean '{matches[0]}'?",
                "suggested_safe_alternative": self.known_models[matches[0]].model_dump()
            }
            
        return {"status": "unknown", "alert": "Model not found in registry. Proceed with caution."}

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
