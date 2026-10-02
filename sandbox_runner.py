import sys
import os
import pickle
import warnings
import io
import zipfile

warnings.filterwarnings("ignore", category=UserWarning)

# ==========================================
# 1. GHOST CLASS: UNIVERSAL MOCKING ENGINE
# ==========================================
class MockClass:
    """Absorbs dependencies and malware probes without crashing."""
    def __init__(self, *args, **kwargs): pass
    def __call__(self, *args, **kwargs): return MockClass()
    def __getattr__(self, name): return MockClass()
    def __setstate__(self, *args, **kwargs): pass
    def __getitem__(self, key): return MockClass()
    def __setitem__(self, key, value): pass
    def __iter__(self): return iter([])
    # Prevent MockClass from breaking string-type checks in pickle internals
    def __str__(self): return "MockClass"
    def __repr__(self): return "MockClass"

class GhostUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        try:
            return super().find_class(module, name)
        except Exception:
            return MockClass

    def persistent_load(self, pid):
        return MockClass()

def safe_ghost_load(file_path):
    """Intelligently unpacks raw pickles AND PyTorch zip archives."""
    if zipfile.is_zipfile(file_path):
        # Hack: It's a modern PyTorch file. Unzip it in memory!
        with zipfile.ZipFile(file_path, 'r') as z:
            # Find the hidden pickle file inside the PyTorch archive
            pkl_files = [n for n in z.namelist() if n.endswith('.pkl')]
            if pkl_files:
                # Load the malware directly from the extracted stream
                with z.open(pkl_files[0]) as f:
                    unpickler = GhostUnpickler(f)
                    return unpickler.load()
            else:
                raise Exception("PyTorch Zip file does not contain a .pkl stream")
    else:
        # It's a standard raw pickle file
        with open(file_path, 'rb') as f:
            unpickler = GhostUnpickler(f)
            return unpickler.load()

# ==========================================
# 2. MAIN EXECUTION LOGIC
# ==========================================
def run_sandbox(model_path):
    try:
        # We don't even need to check extensions anymore, the unpickler handles it all
        obj = safe_ghost_load(model_path)

        if isinstance(obj, dict):
            print("Safely loaded state_dict. Skipping execution.")
        elif callable(obj):
            print("Loaded object is callable. Executing fuzzing logic...")
            try:
                for _ in range(15):
                    obj()
            except Exception as e:
                print(f"Fuzzing interrupted (expected during detonation): {e}")
        else:
            print(f"Loaded object is not callable ({type(obj).__name__}). Skipping execution.")

    except Exception as e:
        print(f"Load failed (missing class defs or invalid format): {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sandbox_runner.py <model_path>")
        sys.exit(1)
    
    run_sandbox(sys.argv[1])
