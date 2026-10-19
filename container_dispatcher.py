import subprocess, json, os, sys, re, pickletools, zipfile, tempfile

try:
    import py7zr
except ImportError:
    py7zr = None

def scan_bytes(data):
    try:
        for op, arg, pos in pickletools.genops(data):
            if op.name == "GLOBAL":
                mod = arg if isinstance(arg, str) else arg.decode('utf-8', 'ignore')
                if any(bad in mod for bad in ('builtins', 'os', 'subprocess', 'sys', 'posix', 'pty', 'compiler')):
                    return True, f"Hostile GLOBAL import: {mod}"
                # THE FIX: Removed '_codecs encode' to allow legitimate PyTorch RNG states
                if mod in ('pickle loads', '_pickle loads', 'marshal loads', 'base64 b64decode', 'importlib import_module'):
                    return True, f"Nested deserialization detected: {mod}"
                    
            if op.name in ('UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE'):
                val = arg if isinstance(arg, str) else arg.decode('utf-8', 'ignore')
                if val in ('eval', 'exec', 'subprocess', 'posix_spawn', '_pickle', 'cPickle', 'marshal'):
                    return True, f"Restricted memory hijack string pushed: {val}"
                if 'exec(' in val or 'eval(' in val or '__import__' in val or 'getattr(' in val:
                    return True, f"Code execution payload detected in string: {val}"
    except Exception:
        pass
    return False, None

def static_bytecode_scan(model_path):
    try:
        with open(model_path, 'rb') as f:
            is_mal, reason = scan_bytes(f.read(5 * 1024 * 1024))
            if is_mal: return True, reason
    except Exception: pass

    if zipfile.is_zipfile(model_path):
        try:
            with zipfile.ZipFile(model_path, 'r') as z:
                for name in z.namelist():
                    is_mal, reason = scan_bytes(z.read(name))
                    if is_mal: return True, f"Smuggled in ZIP -> {reason}"
        except Exception: pass

    if py7zr and py7zr.is_7zfile(model_path):
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                with py7zr.SevenZipFile(model_path, mode='r') as z:
                    z.extractall(path=tmpdir)
                for root, _, files in os.walk(tmpdir):
                    for fname in files:
                        with open(os.path.join(root, fname), 'rb') as ef:
                            is_mal, reason = scan_bytes(ef.read(5 * 1024 * 1024))
                            if is_mal: return True, f"Smuggled in 7z -> {reason}"
        except Exception: pass

    return False, None

def detonate_in_container(model_path):
    abs_path = os.path.abspath(model_path)
    filename = os.path.basename(model_path)

    is_malicious, reason = static_bytecode_scan(abs_path)
    if is_malicious:
        return {"model_name": filename, "format": "PICKLE", "verdict": "MALICIOUS", "confidence": "HIGH", "summary": f"Static pre-check caught payload: {reason}"}

    cmd = [
        "docker", "run", "--rm",
        "--add-host=host.docker.internal:host-gateway",
        "--network=bridge", "--memory=4g", "--cpus=2.0",
        "-v", f"{abs_path}:/target/{filename}:ro",
        "vigilant-sandbox", f"/target/{filename}"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15.0)
        output = result.stdout.strip()
        match = re.search(r'(\{[\s\S]*\})', output)
        if match: 
            res = json.loads(match.group(1))
            if "password required" in res.get("summary", "").lower() or "encrypted" in res.get("summary", "").lower():
                # THE FIX: Zero Trust means unscannable black boxes get blocked.
                res["verdict"] = "MALICIOUS"
                res["summary"] = "Policy Violation: Encrypted/Unscannable archive"
            return res

        return {"model_name": filename, "format": "UNKNOWN", "verdict": "SUSPICIOUS", "summary": f"Container failed. stderr: {result.stderr.strip()}"}
    except subprocess.TimeoutExpired:
        return {"model_name": filename, "verdict": "MALICIOUS", "summary": "Execution timed out (evasion sleep attempt)."}
    except Exception as e:
        return {"model_name": filename, "verdict": "SUSPICIOUS", "summary": f"Host error: {str(e)}"}

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    print(json.dumps(detonate_in_container(sys.argv[1]), indent=2))
