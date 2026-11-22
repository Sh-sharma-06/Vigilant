import re

with open('model_dispatcher.py.orig', 'r') as f:
    disp = f.read()

helper = '''def _parses_as_pickle(path, limit=1 << 20):
    import pickletools
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit)
        n = 0
        for op, arg, pos in pickletools.genops(data):
            n += 1
            if op.name == "STOP":
                return n > 1
        return False
    except Exception:
        return False\n\n'''

if '_parses_as_pickle' not in disp:
    disp = disp.replace('def sniff_format(', helper + 'def sniff_format(')

disp = re.sub(r'if head\[0\] == 0x08:\s*return "ONNX"\s*return "UNKNOWN"',
              'if head[0] == 0x08:\n        return "ONNX"\n    if _parses_as_pickle(path):\n        return "PICKLE"\n    return "UNKNOWN"', disp)

with open('model_dispatcher.py', 'w') as f:
    f.write(disp)
print("Dispatcher patched.")
