#!/usr/bin/env python3
"""
test_scanner.py — sanity-check pickle_scanner.py against a benign pickle
and a malicious pickle (standard os.system-via-__reduce__ test payload,
the same technique used in essentially every pickle-scanner test suite,
e.g. picklescan's own tests).

NOTE: This script only CREATES pickle files via pickle.dumps(); it never
calls pickle.load() on the malicious one. Creating a pickle does not
execute anything — only loading/unpickling it does. The scanner itself
never loads the file either (pickletools.genops just reads opcodes),
which is exactly the property that makes it safe to run on untrusted input.
"""

import pickle
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path

OUT_DIR = Path(__file__).parent / "test_files"
OUT_DIR.mkdir(exist_ok=True)


def make_benign():
    """Mimics a real state_dict: an OrderedDict of plain lists/floats.
    No custom classes, no torch dependency needed — just the same
    allowlisted primitives (OrderedDict, dict, list) a real checkpoint
    is built from once you strip away tensor storage."""
    state_dict = OrderedDict()
    state_dict["layer1.weight"] = [[0.1, 0.2], [0.3, 0.4]]
    state_dict["layer1.bias"] = [0.0, 0.0]
    path = OUT_DIR / "benign_model.pkl"
    with open(path, "wb") as f:
        pickle.dump(state_dict, f)
    return path


def make_malicious():
    # Use the real os.system target directly so the GLOBAL opcode
    # actually points at "os.system" / "posix.system", matching what a
    # real attack looks like.
    payload = _RealReduce()
    path = OUT_DIR / "malicious_model.pkl"
    with open(path, "wb") as f:
        pickle.dump(payload, f)
    return path


class _RealReduce:
    def __reduce__(self):
        import os
        return (os.system, ("echo THIS_WOULD_HAVE_RUN_IF_LOADED",))


def main():
    benign_path = make_benign()
    malicious_path = make_malicious()

    print("=== Benign file ===")
    subprocess.run([sys.executable, str(Path(__file__).parent / "pickle_scanner.py"), str(benign_path)])

    print("\n=== Malicious file ===")
    subprocess.run([sys.executable, str(Path(__file__).parent / "pickle_scanner.py"), str(malicious_path)])


if __name__ == "__main__":
    main()
