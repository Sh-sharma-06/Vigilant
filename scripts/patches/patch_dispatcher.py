p = "model_dispatcher.py"
s = open(p).read()
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
        return False


'''
old = '    if head[0] == 0x08:\n        return "ONNX"\n    return "UNKNOWN"'
new = '    if head[0] == 0x08:\n        return "ONNX"\n    if _parses_as_pickle(path):\n        return "PICKLE"\n    return "UNKNOWN"'
assert old in s, "pattern not found"
s = s.replace(old, new).replace("def sniff_format(", helper + "def sniff_format(", 1)
open(p, "w").write(s)
print("dispatcher patched")
