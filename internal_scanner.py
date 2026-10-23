import sys, os, io, pickle, pickletools, zipfile, json, builtins, atexit

def lethal_exit(code=0): raise Exception("Blocked exit")
sys.exit = os._exit = lethal_exit

# Kernel Spoofing
_orig_open = builtins.open
def spoofed_open(file, *args, **kwargs):
    if "cgroup" in str(file): return io.StringIO("0::/\n")
    if "uptime" in str(file): return io.StringIO("345600.00 1382400.00\n")
    return _orig_open(file, *args, **kwargs)
builtins.open = spoofed_open

THREAT_DETECTED = None
AUDIT_ACTIVE = False
NETWORK_EVENTS = []

def strict_audit(event, args):
    global THREAT_DETECTED
    if not AUDIT_ACTIVE: return
    if event in ('socket.connect', 'socket.socket'):
        NETWORK_EVENTS.append(f"{event}:{args}")
        if not THREAT_DETECTED:
            THREAT_DETECTED = f"Intercepted network capability: {event}"
        return
    if event in ('os.system', 'os.posix_spawn', 'subprocess.Popen', 'posix.system', 'builtins.eval', 'builtins.exec', 'pty.spawn', 'cpython.run_command'):
        THREAT_DETECTED = f"Intercepted capability: {event}"
        raise Exception(THREAT_DETECTED)
    if event == 'open' and args and '.aws' in str(args[0]):
        THREAT_DETECTED = f"Canary access: {args[0]}"
        raise Exception(THREAT_DETECTED)
sys.addaudithook(strict_audit)

RESTRICTED_MODULES = {'os', 'posix', 'nt', 'subprocess', 'pty', 'socket', 'urllib', 'requests', 'sys', 'webbrowser', 'timeit', 'pdb', 'platform', 'shutil', 'importlib', 'runpy', 'ctypes', 'httplib', 'aiohttp', 'venv'}
RESTRICTED_BUILTINS = {'eval', 'exec', 'compile', '__import__', 'getattr', 'setattr', 'globals', 'locals', 'vars'}

def is_truncated_inert_stream(data):
    has_exec_opcode = False
    try:
        for op, arg, pos in pickletools.genops(data):
            if op.name in ('REDUCE', 'BUILD', 'INST', 'OBJ', 'NEWOBJ', 'NEWOBJ_EX', 'STOP'):
                has_exec_opcode = True
    except Exception as e:
        err = str(e).lower()
        if ("expected" in err and "bytes" in err and "but only" in err) and not has_exec_opcode:
            return True
    return False

def scan_opcodes(data):
    if is_truncated_inert_stream(data):
        return False, None
    string_stack = []
    try:
        for op, arg, pos in pickletools.genops(data):
            if op.name == "GLOBAL":
                parts = arg.split(" ", 1) if isinstance(arg, str) else arg.decode('utf-8', 'ignore').split(" ", 1)
                if len(parts) > 1:
                    mod, name = parts[0], parts[1]
                    base_mod = mod.split('.')[0]
                    if base_mod in RESTRICTED_MODULES or (base_mod in ('builtins', '__builtin__') and name in RESTRICTED_BUILTINS):
                        return True, f"Hostile static GLOBAL -> {mod}.{name}"
            elif op.name in ('UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE', 'STRING', 'BINSTRING', 'SHORT_BINSTRING'):
                val = arg if isinstance(arg, str) else arg.decode('utf-8', 'ignore')
                string_stack.append(val)
                if len(string_stack) > 16:
                    string_stack.pop(0)
            elif op.name == "STACK_GLOBAL" and len(string_stack) >= 2:
                mod, name = string_stack[-2], string_stack[-1]
                base_mod = mod.split('.')[0]
                if base_mod in RESTRICTED_MODULES or (base_mod in ('builtins', '__builtin__') and name in RESTRICTED_BUILTINS):
                    return True, f"Hostile static STACK_GLOBAL -> {mod}.{name}"
    except: pass
    return False, None

class MockClass:
    def __init__(self, *args, **kwargs): pass
    def __call__(self, *args, **kwargs): return MockClass()
    def __getattr__(self, name): return MockClass()

class GhostUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        global THREAT_DETECTED
        base_mod = module.split('.')[0]
        if base_mod in ('socket', 'urllib', 'requests', 'http', 'httplib', 'aiohttp'):
            if not THREAT_DETECTED:
                THREAT_DETECTED = f"Blocked dynamic network import -> {module}.{name}"
            try: return super().find_class(module, name)
            except: return MockClass()
        if base_mod in RESTRICTED_MODULES or (base_mod in ('builtins', '__builtin__') and name in RESTRICTED_BUILTINS):
            THREAT_DETECTED = f"Blocked dynamic import -> {module}.{name}"
            raise Exception(THREAT_DETECTED)
        try: return super().find_class(module, name)
        except: return MockClass()
    def persistent_load(self, pid): return MockClass()

def deep_fuzz(obj, depth=0, visited=None):
    if visited is None: visited = set()
    if id(obj) in visited or depth > 5: return
    visited.add(id(obj))
    if type(obj).__name__ == "MockClass": return

    if hasattr(obj, "__dir__") or hasattr(obj, "__dict__"):
        try:
            for attr_name in ("forward", "predict", "transform", "__reduce__", "__setstate__", "__call__", "fit", "evaluate", "run"):
                if hasattr(obj, attr_name):
                    attr = getattr(obj, attr_name)
                    if callable(attr):
                        for args in [(), (MockClass(),), ({"payload": "test", "state": MockClass()},)]:
                            try: attr(*args)
                            except Exception: pass
        except: pass

    if isinstance(obj, dict): [deep_fuzz(v, depth+1, visited) for v in obj.values()]
    elif isinstance(obj, (list, tuple, set)): [deep_fuzz(v, depth+1, visited) for v in obj]
    elif hasattr(obj, "__dict__"): [deep_fuzz(v, depth+1, visited) for v in obj.__dict__.values()]

def run():
    global AUDIT_ACTIVE, THREAT_DETECTED
    path = sys.argv[1]
    devnull = os.open(os.devnull, os.O_WRONLY)
    old_out, old_err = os.dup(1), os.dup(2)
    os.dup2(devnull, 1); os.dup2(devnull, 2)

    try:
        streams = []
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, 'r') as z:
                for n in z.namelist():
                    if not n.endswith('/'):
                        try:
                            streams.append(z.read(n))
                        except RuntimeError as re_err:
                            if "encrypted" in str(re_err).lower() or "password" in str(re_err).lower():
                                with _orig_open(path, 'rb') as rf:
                                    raw_zip = rf.read()
                                if any(s in raw_zip for s in (b"posix", b"system", b"builtins", b"__builtin__", b"eval", b"subprocess")):
                                    raise Exception("ZIP 0x1 encryption flag spoofing detected")
                                continue
                            raise re_err
            if not streams:
                os.dup2(old_out, 1); os.dup2(old_err, 2)
                return {"verdict": "BENIGN", "summary": "Encrypted archive (inert without password)"}
        else:
            with _orig_open(path, 'rb') as f: streams = [f.read()]

        valid_streams = [s for s in streams if not is_truncated_inert_stream(s)]
        if not valid_streams:
            os.dup2(old_out, 1); os.dup2(old_err, 2)
            return {"verdict": "BENIGN", "summary": "Corrupted/truncated stream (no executable opcodes)"}

        for s in valid_streams:
            bad, reason = scan_opcodes(s)
            if bad: THREAT_DETECTED = reason

        AUDIT_ACTIVE = True
        for s in valid_streams:
            unp = GhostUnpickler(io.BytesIO(s))
            while True:
                try: deep_fuzz(unp.load())
                except (EOFError, StopIteration): break
                except Exception: break

        atexit._run_exitfuncs()
        AUDIT_ACTIVE = False

        try:
            with _orig_open('/tmp/.aws/credentials', 'r') as f:
                if "AKIAIOSFODNN7EXAMPLE" not in f.read(): THREAT_DETECTED = "AWS Canary tripped"
        except: THREAT_DETECTED = "AWS Canary missing"

        if THREAT_DETECTED: raise Exception(THREAT_DETECTED)

        os.dup2(old_out, 1); os.dup2(old_err, 2)
        return {"verdict": "BENIGN", "summary": "Clean execution"}
    except Exception as e:
        AUDIT_ACTIVE = False
        os.dup2(old_out, 1); os.dup2(old_err, 2)
        return {"verdict": "MALICIOUS", "summary": str(e)}

if __name__ == "__main__":
    print(json.dumps(run()))
