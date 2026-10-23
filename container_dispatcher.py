import subprocess, json, os, sys, re, pickletools, zipfile, tempfile, uuid

try:
    import py7zr
except ImportError:
    py7zr = None

try:
    from inspectors.multi_format_scanner import identify_true_format, scan_hdf5, scan_onnx, scan_safetensors, scan_gguf
except ImportError:
    identify_true_format = None

# =========================================================================
# CLAUDE FIX 1: Host-Side Archive Hardening (Zip-Bomb Prevention)
# =========================================================================
MAX_UNCOMPRESSED_SIZE = 10 * 1024 * 1024 * 1024 # 10 GB
MAX_FILES = 10000
MAX_COMPRESSION_RATIO = 200

DANGEROUS_BUILTINS = {
    'eval', 'exec', 'execfile', 'compile', '__import__', 'open',
    'getattr', 'setattr', 'delattr', 'globals', 'locals', 'vars',
    'input', 'raw_input', 'breakpoint', 'help', 'dir'
}

HOSTILE_MODULES = {
    'os', 'subprocess', 'sys', 'posix', 'nt', 'mac', 'pty', 'compiler',
    'socket', 'urllib', 'urllib2', 'urllib3', 'requests', 'aiohttp',
    'http', 'ftplib', 'telnetlib', 'smtplib', 'venv', 'shutil', 'tempfile',
    'ctypes', 'multiprocessing', 'threading', 'asyncio', 'webbrowser',
    'code', 'codeop', 'commands', 'popen2', 'bdb', 'pdb', 'runpy', 'imp', 'importlib'
}

HOSTILE_TARGETS = {
    'pickle loads', '_pickle loads', 'cPickle loads', 'marshal loads',
    'base64 b64decode', 'importlib import_module', 'pickle.loads',
    '_pickle.loads', 'cPickle.loads', 'marshal.loads', 'base64.b64decode',
    'importlib.import_module', 'torch._inductor.codecache compile_file',
    'torch._inductor.codecache.compile_file', 'torch.serialization load',
    'torch.serialization.load', 'functools partial', 'functools.partial'
}

def check_zip_bomb(zip_ref):
    """Verifies archive metadata against zip-bomb thresholds before extracting."""
    total_size = 0
    total_files = len(zip_ref.infolist())

    if total_files > MAX_FILES:
        raise Exception(f"Archive exceeds maximum file count ({total_files} > {MAX_FILES})")

    for info in zip_ref.infolist():
        total_size += info.file_size

        if info.compress_size > 0:
            ratio = info.file_size / info.compress_size
            if ratio > MAX_COMPRESSION_RATIO:
                raise Exception(f"Suspicious compression ratio ({ratio}:1)")

    if total_size > MAX_UNCOMPRESSED_SIZE:
        raise Exception("Archive exceeds maximum uncompressed size")

def check_mod_target(mod_str):
    """Evaluates a 'module attr' pair from either GLOBAL or Protocol 4 STACK_GLOBAL."""
    parts = mod_str.replace('.', ' ').split()
    base_mod = parts[0].lower() if parts else ""
    attr = parts[-1].lower() if len(parts) > 1 else ""

    if base_mod in ('builtins', '__builtin__'):
        if attr in DANGEROUS_BUILTINS:
            return True, f"Hostile builtin callable: {mod_str}"
        return False, None

    if base_mod in HOSTILE_MODULES:
        return True, f"Hostile GLOBAL import: {mod_str}"

    if mod_str in HOSTILE_TARGETS or f"{base_mod} {attr}" in HOSTILE_TARGETS:
        return True, f"Dangerous deserialization gadget: {mod_str}"

    if 'inductor' in mod_str.lower() or 'codecache' in mod_str.lower():
        return True, f"Compiler gadget abuse: {mod_str}"

    return False, None

def is_printable_text(s):
    """Distinguishes true source/command strings from raw binary tensor blobs."""
    if not s or len(s) < 2:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in '\n\r\t')
    return (printable / len(s)) > 0.85

def strip_zip_encryption_bits(raw_bytes):
    """
    Zeroes out Bit 0 (0x01 encryption flag) and Bit 6 (0x40 strong encryption)
    in both Local File Headers (PK\x03\x04) and Central Directory Headers (PK\x01\x02).
    If the archive was merely bit-flipped to evade scanners, it will now extract cleanly!
    """
    b = bytearray(raw_bytes)
    i = 0
    n = len(b)
    while i < n - 30:
        # Local File Header: PK\x03\x04 (flags at offset +6)
        if b[i:i+4] == b'PK\x03\x04':
            b[i+6] &= ~0x41
            i += 30
        # Central Directory Header: PK\x01\x02 (flags at offset +8)
        elif b[i:i+4] == b'PK\x01\x02':
            b[i+8] &= ~0x41
            i += 46
        else:
            i += 1
    return bytes(b)

def scan_bytes(data):
    findings = []
    stack = []
    memo = {}
    has_reduce_or_stop = False
    stream_corrupted = False

    try:
        for op, arg, pos in pickletools.genops(data):
            name = op.name
            if name in ('REDUCE', 'BUILD', 'INST', 'OBJ', 'NEWOBJ', 'NEWOBJ_EX', 'STOP'):
                has_reduce_or_stop = True

            if name == "GLOBAL":
                mod = arg if isinstance(arg, str) else arg.decode('utf-8', 'ignore')
                is_mal, reason = check_mod_target(mod)
                if is_mal:
                    findings.append(reason)
                stack.append(mod)

            elif name in ('UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE', 'BINUNICODE8', 'STRING', 'BINSTRING', 'SHORT_BINSTRING'):
                val = arg if isinstance(arg, str) else arg.decode('utf-8', 'ignore')
                stack.append(val)

                # Only run command/code regexes on actual printable text strings (ignores binary RNG/weight tensors)
                if name in ('UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE', 'BINUNICODE8') or is_printable_text(val):
                    if val in ('eval', 'exec', 'subprocess', 'posix_spawn', '_pickle', 'cPickle', 'marshal', 'system', 'popen', 'compile_file', 'weights_only'):
                        findings.append(f"Restricted memory hijack string pushed: {val}")
                    if is_printable_text(val) and any(x in val for x in ('exec(', 'eval(', '__import__(', 'getattr(', 'system(', 'os.popen(', 'subprocess.', 'sh -c', '/bin/sh', '/bin/bash')):
                        findings.append(f"Code execution payload detected in string: {val[:80]}")
                    if is_printable_text(val) and re.search(r'\$\([a-zA-Z0-9_/.-]+', val):
                        findings.append(f"Shell command substitution detected: {val[:80]}")

            elif name == "MEMOIZE":
                if stack:
                    memo[len(memo)] = stack[-1]

            elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                if stack:
                    memo[arg] = stack[-1]

            elif name in ("GET", "BINGET", "LONG_BINGET"):
                stack.append(memo.get(arg, ""))

            elif name == "STACK_GLOBAL":
                if len(stack) >= 2:
                    attr_name = str(stack.pop())
                    mod_name = str(stack.pop())
                    combined = f"{mod_name} {attr_name}"
                    is_mal, reason = check_mod_target(combined)
                    if is_mal:
                        findings.append(reason)
                    stack.append(combined)

            else:
                # Maintain bounded stack for other opcodes
                if len(stack) > 64:
                    stack = stack[-32:]

    except Exception as e:
        err_msg = str(e).lower()
        if "expected" in err_msg and "bytes in a" in err_msg and "but only" in err_msg:
            stream_corrupted = True

    if stream_corrupted and not has_reduce_or_stop:
        return False, None

    if findings:
        return True, findings[0]

    return False, None

def static_bytecode_scan(model_path):
    ext = os.path.splitext(model_path)[1].lower()

    try:
        with open(model_path, 'rb') as f:
            raw_data = f.read(5 * 1024 * 1024)

        # 1. 7z Container Inspection (extract via py7zr if installed, or scan underlying stream)
        if raw_data.startswith(b"7z\xbc\xaf'\x1c") or ext == '.7z':
            if py7zr:
                try:
                    with py7zr.SevenZipFile(model_path, mode='r') as z7:
                        for fname, bio in z7.readall().items():
                            is_mal, reason = scan_bytes(bio.read())
                            if is_mal:
                                return True, f"Smuggled in 7z -> {reason}"
                except Exception as e:
                    return True, f"7z Archive Policy Violation: {str(e)}"
            return True, "Unsupported 7z archive container policy violation"

        # 2. Polyglot / File Header Masquerading
        if ext in ('.pt', '.pth', '.bin', '.pkl', '.pickle') and raw_data.startswith((b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'%PDF', b'\x7fELF', b'MZ')):
            return True, "File header masquerading / polyglot anomaly detected"

        if not zipfile.is_zipfile(model_path):
            is_mal, reason = scan_bytes(raw_data)
            if is_mal:
                return True, reason
    except Exception:
        pass

    if zipfile.is_zipfile(model_path):
        try:
            with zipfile.ZipFile(model_path, 'r') as z:
                check_zip_bomb(z)
                for name in z.namelist():
                    try:
                        member_bytes = z.read(name)
                    except RuntimeError as re_err:
                        if "encrypted" in str(re_err).lower() or "password" in str(re_err).lower():
                            # General defense against ZIP 0x1 / 0x40 bit-flipping:
                            # Strip the encryption flag bits in memory and attempt extraction!
                            with open(model_path, 'rb') as rf:
                                stripped_zip_bytes = strip_zip_encryption_bits(rf.read())
                            try:
                                import io
                                with zipfile.ZipFile(io.BytesIO(stripped_zip_bytes), 'r') as sz:
                                    unmasked_bytes = sz.read(name)
                                # If it extracted cleanly without a password, the encryption bit was SPOOFED!
                                is_mal, reason = scan_bytes(unmasked_bytes)
                                return True, f"ZIP encryption flag bit-flipping detected ({reason or 'unencrypted stream inside flagged archive'})"
                            except Exception:
                                # Genuinely encrypted archive (fails CRC/decompression without password)
                                continue
                        raise re_err
                    is_mal, reason = scan_bytes(member_bytes)
                    if is_mal:
                        return True, f"Smuggled in ZIP -> {reason}"
        except Exception as e:
            return True, f"Archive Policy Violation: {str(e)}"

    return False, None

def detonate_in_container(model_path):
    abs_path = os.path.abspath(model_path)
    filename = os.path.basename(model_path)
    repo_root = os.path.dirname(os.path.abspath(__file__))
    fakenet_log = os.path.join(repo_root, "logs", "network_telemetry.json")

    if os.path.exists(fakenet_log):
        try:
            open(fakenet_log, 'w').close()
        except Exception:
            pass

    detected_format = "PICKLE"
    if identify_true_format:
        try:
            detected_format = identify_true_format(abs_path)
            if detected_format in ("HDF5", "ONNX", "SAFETENSORS", "GGUF"):
                scanner_map = {"HDF5": scan_hdf5, "ONNX": scan_onnx, "SAFETENSORS": scan_safetensors, "GGUF": scan_gguf}
                is_mal, reason, _ = scanner_map[detected_format](abs_path)
                if is_mal:
                    return {"model_name": filename, "format": detected_format, "verdict": "MALICIOUS", "summary": reason}
        except Exception:
            pass

    is_malicious, reason = static_bytecode_scan(abs_path)
    if is_malicious:
        deterministic_markers = ("Hostile", "gadget", "masquerading", "7z", "Smuggled", "Restricted", "Archive Policy", "Embedded shell", "Code execution", "spoofing")
        if os.environ.get("VIGILANT_ENABLE_LLM") == "1" and not any(m in str(reason) for m in deterministic_markers):
            try:
                from triage_agent import TriageAgent, Verdict
                agent = TriageAgent()
                triage_res = agent.triage(
                    static_scanner_output={"file": filename, "reason": reason},
                    telemetry={}
                )
                if triage_res.verdict == Verdict.SAFE:
                    is_malicious = False
            except Exception:
                pass

        if is_malicious:
            return {"model_name": filename, "format": detected_format, "verdict": "MALICIOUS", "summary": reason}

    scanner_script = os.path.join(repo_root, "internal_scanner.py")

    # Unique container name for tracking/killing
    container_name = f"vigilant_sandbox_{uuid.uuid4().hex[:8]}"

    # Realistic dummy keys injected into tmpfs
    setup_and_run = (
        "mkdir -p /tmp/.aws && "
        "echo '[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > /tmp/.aws/credentials && "
        f"python3 /internal_scanner.py '/target/{filename}'"
    )

    # Check if vigilant-net exists; fall back to --network=none if setup_fakenet.sh hasn't been run yet
    net_check = subprocess.run(["docker", "network", "inspect", "vigilant-net"], capture_output=True)
    resolv_path = os.path.join(repo_root, "resolv.fakenet")
    network_flags = ["--network=vigilant-net", "--dns=172.20.0.2", "-v", f"{resolv_path}:/etc/resolv.conf:ro"] if (net_check.returncode == 0 and os.path.exists(resolv_path)) else ["--network=none"]

    # CLAUDE FIX 2, 4 + gVisor: Absolute lockdown
    cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--runtime=runsc",           # gVisor User-Space Kernel
        *network_flags,              # Air-gapped FakeNet or none
        "--memory=4g", "--memory-swap=4g", # Hard limits
        "--cpus=2.0",
        "--pids-limit=100",          # Anti-fork bomb
        "--cap-drop=ALL",            # Drop all privileges
        "--security-opt=no-new-privileges",
        "--read-only",               # Lock the filesystem
        "--tmpfs", "/tmp:exec",      # Executable temporary space
        "--user", "1000:1000",       # Non-root execution
        "-e", "HOME=/tmp",
        "-v", f"{abs_path}:/target/{filename}:ro",
        "-v", f"{scanner_script}:/internal_scanner.py:ro",
        "vigilant-sandbox",
        "sh", "-c", setup_and_run
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15.0)

        if os.path.exists(fakenet_log) and os.path.getsize(fakenet_log) > 0:
            return {"model_name": filename, "format": detected_format, "verdict": "MALICIOUS", "summary": "C2 network traffic intercepted"}

        output = result.stdout.strip()
        match = re.search(r'(\{[\s\S]*\})', output)
        if match:
            res = json.loads(match.group(1))
            return res
        return {"model_name": filename, "format": detected_format, "verdict": "MALICIOUS", "summary": "Sandbox evasive crash"}

    except subprocess.TimeoutExpired:
        # Properly kill the orphaned container
        subprocess.run(["docker", "kill", container_name], capture_output=True)
        return {"model_name": filename, "format": detected_format, "verdict": "MALICIOUS", "summary": "Execution timed out (evasion sleep attempt)"}

    except Exception as e:
        # Differentiate between OOM kills (large models) and errors
        inspect_res = subprocess.run(["docker", "inspect", container_name], capture_output=True, text=True)
        if "OOMKilled\": true" in inspect_res.stdout:
            return {"model_name": filename, "format": detected_format, "verdict": "ERROR", "summary": "Container ran out of memory (OOMKilled)"}

        return {"model_name": filename, "format": detected_format, "verdict": "MALICIOUS", "summary": f"Host error: {str(e)}"}

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    print(json.dumps(detonate_in_container(sys.argv[1]), indent=2))
