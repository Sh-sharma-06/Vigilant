import zipfile
import pickletools
import sys

# Unzip the PyTorch file and disassemble the hidden pickle stream
with zipfile.ZipFile(sys.argv[1]) as zf:
    for name in zf.namelist():
        if name.endswith(".pkl") or name.endswith("/data.pkl"):
            print(f"=== Disassembly of {name} ===")
            pickletools.dis(zf.open(name))
