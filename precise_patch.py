with open('model_dispatcher.py', 'r') as f:
    lines = f.readlines()

with open('model_dispatcher.py', 'w') as f:
    for line in lines:
        # Inject the helper function right before sniff_format
        if 'def sniff_format' in line:
            f.write('def _parses_as_pickle(path, limit=1 << 20):\n')
            f.write('    import pickletools\n')
            f.write('    try:\n')
            f.write('        with open(path, "rb") as fh:\n')
            f.write('            data = fh.read(limit)\n')
            f.write('        n = 0\n')
            f.write('        for op, arg, pos in pickletools.genops(data):\n')
            f.write('            n += 1\n')
            f.write('            if op.name == "STOP":\n')
            f.write('                return n > 1\n')
            f.write('        return False\n')
            f.write('    except Exception:\n')
            f.write('        return False\n\n')
        
        # Capture exact indentation of the original line and match it
        if 'return "UNKNOWN"' in line and 'def ' not in line:
            indent = line[:len(line) - len(line.lstrip())]
            f.write(f'{indent}if _parses_as_pickle(path):\n')
            f.write(f'{indent}    return "PICKLE"\n')
        
        f.write(line)
