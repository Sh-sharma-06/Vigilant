import os
import random
import sys
from pathlib import Path

import torch

# Dynamic loading may execute pickle payloads. Refuse host execution even when
# this module is invoked directly by mistake.
if not os.path.exists("/.dockerenv"):
    sys.exit(
        "CRITICAL SECURITY EXCEPTION: Dynamic analysis must ONLY be executed "
        "inside the isolated Docker sandbox. Halting execution."
    )


def main(model_path: str) -> int:
    # Full-module PyTorch archives may reference a class beside the model. The
    # runner mounts only that directory, and imports remain contained in Docker.
    model_directory = str(Path(model_path).resolve().parent)
    if model_directory not in sys.path:
        sys.path.insert(0, model_directory)
    try:
        # This deliberately permits pickle execution and must run only in Docker.
        loaded_obj = torch.load(model_path, map_location="cpu", weights_only=False)
    except Exception as error:
        print(f"Load failed (missing class defs or invalid format): {error}")
        return 1

    if isinstance(loaded_obj, dict):
        print("Safely loaded state_dict. Skipping execution.")
        return 0
    if not callable(loaded_obj):
        print(f"Loaded object is not callable ({type(loaded_obj).__name__}). Skipping execution.")
        return 0

    # Five calls retain coverage for common delayed triggers while keeping the
    # total randomized instead of relying on the demo's old fixed nine passes.
    num_calls = random.randint(5, 15)
    print(f"Fuzzing {num_calls} inference calls.")
    for _ in range(num_calls):
        try:
            dummy_input = torch.randn(1, random.choice([3, 10, 16, 64]))
            loaded_obj(dummy_input)
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python run_model.py <model_file>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
