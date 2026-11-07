"""
inspectors/keras_scanner.py
Static scanner for Keras v3 (.keras) archives. Never loads or executes the model.
"""
import base64, json, re, tempfile, zipfile

MAX_CONFIG_BYTES   = 32 * 2**20     # config.json / metadata.json size cap
MAX_CONFIG_RATIO   = 1000           # compression ratio cap, config files only
MAX_MEMBERS        = 10_000
MAX_DEPTH          = 200            # JSON nesting guard

ALLOWED_MODULE_PREFIXES = ("keras", "tensorflow.keras", "tf_keras")
DANGEROUS_NAMES = {
    "os", "posix", "nt", "sys", "subprocess", "socket", "eval", "exec", "compile",
    "__import__", "builtins", "system", "popen", "urllib", "requests", "shutil",
    "pty", "ctypes", "importlib", "open", "getattr", "pickle", "marshal", "base64",
}
IDENT = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{1,40}")
RANK = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


def _lambda_bytes(node):
    cfg = node.get("config") if isinstance(node.get("config"), dict) else node
    code = cfg.get("code")
    if not isinstance(code, str):
        return None
    return base64.b64decode(code, validate=False)


MAX_LAMBDA_MARSHAL_BYTES = 1 << 20   # never unmarshal anything larger than 1 MiB


def _lambda_evidence(raw, trail):
    """Static evidence for a Lambda payload. Never executes the code object."""
    entry = {"path": trail or "/"}
    if not raw:
        entry["error"] = "no code payload"
        return entry
    if len(raw) > MAX_LAMBDA_MARSHAL_BYTES:
        entry["error"] = "payload too large to disassemble"
        return entry
    try:
        import dis, marshal, types
        code_obj = marshal.loads(raw)
        names, consts, todo, seen = [], [], [code_obj], 0
        while todo and seen < 20:
            co = todo.pop(); seen += 1
            for n in co.co_names:
                if n not in names:
                    names.append(n)
            for c in co.co_consts:
                if isinstance(c, types.CodeType):
                    todo.append(c)
                else:
                    consts.append(repr(c)[:80])
        entry.update(co_names=names[:50], co_consts=consts[:50],
                     co_varnames=list(code_obj.co_varnames)[:50],
                     dis=dis.Bytecode(code_obj).dis()[:4000])
    except Exception as exc:
        entry["error"] = type(exc).__name__
    return entry


def _walk(o, findings, trail="", depth=0, lambda_details=None):
    if lambda_details is None:
        lambda_details = []
    if depth > MAX_DEPTH:
        findings.append(("SUSPICIOUS", f"config nested deeper than {MAX_DEPTH}"))
        return
    if isinstance(o, dict):
        cn = o.get("class_name")
        if cn == "Lambda":
            findings.append(("SUSPICIOUS", f"Lambda layer at {trail or '/'}"))
        if cn == "__lambda__":
            try:
                raw = _lambda_bytes(o)
                lambda_details.append(_lambda_evidence(raw, trail))
                names = {m.decode() for m in IDENT.findall(raw or b"")}
                hits = sorted(names & DANGEROUS_NAMES)
                if hits:
                    findings.append(("MALICIOUS", f"lambda code references {hits} at {trail}"))
                else:
                    findings.append(("SUSPICIOUS", f"embedded lambda code at {trail}"))
            except Exception:
                findings.append(("SUSPICIOUS", f"undecodable lambda payload at {trail}"))
        mod = o.get("module")
        if isinstance(mod, str) and mod and not mod.startswith(ALLOWED_MODULE_PREFIXES):
            findings.append(("SUSPICIOUS", f"non-keras module '{mod}' at {trail}"))
        rn = o.get("registered_name")
        if isinstance(rn, str) and rn.startswith("Custom>"):
            findings.append(("SUSPICIOUS", f"custom registered object '{rn}' at {trail}"))
        for k, v in o.items():
            if "unsafe" in str(k).lower():
                findings.append(("SUSPICIOUS", f"unsafe-deserialization key '{k}' at {trail}"))
            _walk(v, findings, f"{trail}/{k}", depth + 1, lambda_details)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            _walk(v, findings, f"{trail}[{i}]", depth + 1, lambda_details)


def _check_weights(zf, name, findings):
    """Optional: needs h5py. Flags external/soft links, external storage, object dtype."""
    try:
        import h5py
    except ImportError:
        return
    with tempfile.NamedTemporaryFile(suffix=".h5") as tmp:
        with zf.open(name) as src:
            while chunk := src.read(1 << 20):
                tmp.write(chunk)
        tmp.flush()
        try:
            with h5py.File(tmp.name, "r") as h:
                stack, seen = [("", h)], 0
                while stack:
                    prefix, grp = stack.pop()
                    for k in grp:
                        seen += 1
                        if seen > 200_000:
                            findings.append(("SUSPICIOUS", "weights file has too many objects"))
                            return
                        path = f"{prefix}/{k}"
                        link = grp.get(k, getlink=True)
                        if isinstance(link, h5py.ExternalLink):
                            findings.append(("MALICIOUS", f"weights file has ExternalLink at {path}"))
                            continue
                        if isinstance(link, h5py.SoftLink):
                            findings.append(("SUSPICIOUS", f"weights file has SoftLink at {path}"))
                            continue
                        obj = grp[k]
                        if isinstance(obj, h5py.Group):
                            stack.append((path, obj))
                        elif isinstance(obj, h5py.Dataset):
                            if obj.dtype.kind == "O":
                                findings.append(("SUSPICIOUS", f"object-dtype dataset {path}"))
                            if obj.external:
                                findings.append(("MALICIOUS", f"external-storage dataset {path}"))
        except OSError:
            findings.append(("SUSPICIOUS", f"weights member {name} is not valid HDF5"))



def scan_keras_v3(path):
    """Returns {"verdict": CLEAN|SUSPICIOUS|MALICIOUS, "findings": [...], "reason": str}"""
    findings = []
    lambda_details = []
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return {"verdict": "SUSPICIOUS", "findings": [], "reason": "corrupt zip",
            "contains_executable_code": False, "lambda_details": [], "remediation": ""}
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            return {"verdict": "SUSPICIOUS", "findings": [], "reason": "too many zip members",
            "contains_executable_code": False, "lambda_details": [], "remediation": ""}
        for i in infos:
            n = i.filename
            if n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/") or ":" in n.split("/")[0]:
                findings.append(("MALICIOUS", f"path traversal member: {n}"))
            if n.lower().endswith((".pkl", ".pickle", ".npy", ".npz", ".zip", ".pt", ".so", ".dll", ".py", ".exe")):
                findings.append(("SUSPICIOUS", f"unexpected member: {n}"))
            if n.endswith(".json"):   # strict limits on small config files only
                if i.file_size > MAX_CONFIG_BYTES:
                    findings.append(("SUSPICIOUS", f"{n} too large"))
                elif i.compress_size and i.file_size / i.compress_size > MAX_CONFIG_RATIO:
                    findings.append(("SUSPICIOUS", f"{n} compression ratio too high"))
        names = zf.namelist()
        if "config.json" not in names:
            findings.append(("SUSPICIOUS", "config.json missing"))
        elif zf.getinfo("config.json").file_size <= MAX_CONFIG_BYTES:
            try:
                cfg = json.loads(zf.read("config.json"))
                _walk(cfg, findings, lambda_details=lambda_details)
            except (ValueError, RecursionError):
                findings.append(("SUSPICIOUS", "config.json unparseable"))
        for n in names:
            if n.endswith((".weights.h5", ".h5")):
                _check_weights(zf, n, findings)
    contains_executable_code = any(
        "Lambda layer at" in msg or "lambda code references" in msg
        or "embedded lambda code" in msg or "undecodable lambda payload" in msg
        for _, msg in findings
    )
    remediation = ("load with safe_mode=True, or re-save the model without the Lambda layer"
                   if contains_executable_code else "")
    verdict = max((f[0] for f in findings), key=RANK.get, default="CLEAN")
    reason = "; ".join(f[1] for f in findings[:5]) or "no issues found in Keras archive"
    return {"verdict": verdict, "findings": findings, "reason": reason,
            "contains_executable_code": contains_executable_code,
            "lambda_details": lambda_details,
            "remediation": remediation}


def classify_zip(path):
    """Look INSIDE the zip: KERAS_V3, PYTORCH_ZIP, ZIP_UNKNOWN or CORRUPT_ZIP."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return "CORRUPT_ZIP"
    base = {n.split("/")[-1] for n in names}
    if "config.json" in base and "metadata.json" in base and any(
            n.endswith((".weights.h5", ".weights.json")) for n in names):
        return "KERAS_V3"
    if any(n.endswith(".pkl") for n in names):
        return "PYTORCH_ZIP"
    return "ZIP_UNKNOWN"