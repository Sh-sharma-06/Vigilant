"""archive_precheck.py - structural pre-check for ZIP-backed model files.

Decides Keras v3 (.keras) archives and ZIPs with no pickle/code members without
sending them to the sandbox. Returns None to fall through to the existing pipeline.
"""
import base64
import json
import os
import re
import tempfile
import zipfile

MAX_MEMBERS = 10_000
MAX_TOTAL_UNCOMPRESSED = 10 * 1024 ** 3     # matches container_dispatcher
MAX_RATIO = 200                             # matches container_dispatcher
RATIO_MIN_MEMBER = 1024 * 1024              # ratio test only on members >= 1 MiB
MAX_CONFIG_BYTES = 64 * 1024 * 1024
MAX_NESTED_BYTES = 2 * 1024 ** 3
MAX_DEPTH = 2
SCAN_CAP = 32 * 1024 * 1024                 # bytes read from non-pickle members

RISKY_EXT = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib", ".dill",
             ".npy", ".npz", ".py", ".pyc", ".pyo", ".so", ".dll", ".dylib",
             ".exe", ".sh", ".bat", ".ps1", ".jar", ".class")
INERT_EXT = (".json", ".csv", ".tsv", ".txt", ".md", ".log", ".png", ".jpg",
             ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".yaml", ".yml")
NESTED_EXT = (".keras", ".h5", ".hdf5", ".onnx", ".gguf", ".safetensors")

BAD_MODULES = {"os", "sys", "posix", "nt", "subprocess", "socket", "urllib",
               "http", "requests", "shutil", "ctypes", "marshal", "pickle",
               "cPickle", "importlib", "runpy", "pty", "webbrowser"}
BAD_BUILTINS = {"eval", "exec", "compile", "__import__", "open", "getattr",
                "input", "breakpoint"}
# marshalled code objects length-prefix names with a byte < 0x20, so a leading
# non-letter guard works.
_DANGEROUS_CODE = re.compile(
    rb"(?<![A-Za-z_])(system|popen|subprocess|eval|exec|__import__|socket|urllib|builtins|compile)")


def _unsafe_name(name):
    n = name.replace("\\", "/")
    return n.startswith("/") or ".." in n.split("/") or re.match(r"^[A-Za-z]:", n) is not None


def _lambda_code_dangerous(code_b64):
    try:
        raw = base64.b64decode(code_b64)
    except Exception:
        return True
    return bool(_DANGEROUS_CODE.search(raw))


def _keras_config_verdict(raw):
    try:
        cfg = json.loads(raw)
    except Exception as exc:
        return "SUSPICIOUS", "LOW", "config.json is not valid JSON (" + type(exc).__name__ + ")"
    stack, lambda_seen = [cfg], False
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        cn, mod = str(node.get("class_name", "")), str(node.get("module", ""))
        if (mod.split(".")[0] in BAD_MODULES
                or (mod == "builtins" and cn in BAD_BUILTINS)
                or ("." in cn and cn.split(".")[0] in BAD_MODULES)):
            return "MALICIOUS", "HIGH", f"config references dangerous callable {mod or '?'}.{cn}"
        if cn == "__lambda__":
            lambda_seen = True
            conf = node.get("config")
            code = conf.get("code") if isinstance(conf, dict) else None
            if code is not None and _lambda_code_dangerous(code):
                return "MALICIOUS", "HIGH", "Lambda layer bytecode references execution primitives"
        elif cn == "Lambda":
            lambda_seen = True
        stack.extend(node.values())
    if lambda_seen:
        return "SUSPICIOUS", "MEDIUM", "Lambda layer with embedded bytecode; review before loading"
    return ("BENIGN", "MEDIUM",
            "Keras v3 archive: config.json has no Lambda/dangerous callables; no pickle/code "
            "members (weights .h5 not opcode-scanned)")


def _extract(zf, info, tmpdir, idx):
    ext = os.path.splitext(info.filename.lower())[1]
    dest = os.path.join(tmpdir, f"member{idx}{ext}")
    written = 0
    with zf.open(info) as src, open(dest, "wb") as out:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > info.file_size:
                raise ValueError("member exceeds its declared size")
            out.write(chunk)
    return dest


def _scan_nested(path, ext, depth):
    """Return (status, detail): MALICIOUS | SUSPICIOUS | CLEAN | UNKNOWN."""
    if ext == ".keras" and zipfile.is_zipfile(path):
        out = inspect_zip(path, depth + 1)
        if out is None:
            return "UNKNOWN", "nested archive needs the full pipeline"
        verdict, conf, _fmt, summary = out
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            return verdict, summary
        return ("CLEAN" if conf != "LOW" else "UNKNOWN"), summary
    try:
        from inspectors import multi_format_scanner as mfs
        fn = {".h5": mfs.scan_hdf5, ".hdf5": mfs.scan_hdf5, ".keras": mfs.scan_hdf5,
              ".onnx": mfs.scan_onnx, ".gguf": mfs.scan_gguf,
              ".safetensors": mfs.scan_safetensors}[ext]
        res = fn(path)
    except Exception as exc:
        return "UNKNOWN", "scanner failed: " + type(exc).__name__
    if isinstance(res, dict):
        if "is_malicious" not in res and "verdict" not in res:
            return "UNKNOWN", "unrecognized scanner result"
        mal = bool(res.get("is_malicious")) or res.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
        why = "; ".join(res.get("reasons", [])) or str(res.get("summary", ""))
    else:
        mal, why = res[0], str(res[1])
    return ("MALICIOUS", why or "structural violation") if mal else ("CLEAN", "")


def inspect_zip(path, depth=0):
    """Return (verdict, confidence, format, summary) or None to fall through."""
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            return "MALICIOUS", "HIGH", "ZIP", f"Archive Policy Violation: {len(infos)} members exceeds limit"
        for i in infos:
            if _unsafe_name(i.filename):
                return "MALICIOUS", "HIGH", "ZIP", f"Archive Policy Violation: path traversal entry {i.filename!r}"
        if any(i.flag_bits & 0x41 for i in infos):
            return None  # encrypted/flag-spoofed: let existing bit-flip defence handle it
        if sum(i.file_size for i in infos) > MAX_TOTAL_UNCOMPRESSED:
            return "MALICIOUS", "HIGH", "ZIP", "Archive Policy Violation: declared uncompressed size exceeds limit"
        for i in infos:
            if i.file_size and not i.compress_size:
                return "MALICIOUS", "HIGH", "ZIP", f"Archive Policy Violation: invalid compressed size for {i.filename!r}"
            if i.file_size >= RATIO_MIN_MEMBER and i.file_size / i.compress_size > MAX_RATIO:
                return "MALICIOUS", "HIGH", "ZIP", f"Archive Policy Violation: compression ratio bomb in {i.filename!r}"

        files = [i for i in infos if not i.is_dir()]
        names = [i.filename for i in files]
        if len(names) != len(set(names)):
            return "SUSPICIOUS", "MEDIUM", "ZIP", "Duplicate member names in archive"
        if any(n.lower().endswith(RISKY_EXT) for n in names):
            return None  # pickle/code present: existing pipeline decides

        if "config.json" in names and ("metadata.json" in names
                                       or any(n.endswith(".weights.h5") for n in names)):
            info = zf.getinfo("config.json")
            if info.file_size > MAX_CONFIG_BYTES:
                return "SUSPICIOUS", "LOW", "KERAS", "[KERAS] config.json larger than cap"
            with zf.open(info) as fh:
                raw = fh.read(MAX_CONFIG_BYTES + 1)
            if len(raw) > MAX_CONFIG_BYTES:
                return "SUSPICIOUS", "LOW", "KERAS", "[KERAS] config.json larger than declared"
            verdict, conf, summary = _keras_config_verdict(raw)
            return verdict, conf, "KERAS", "[KERAS] " + summary

        notes, nested_clean = [], 0
        with tempfile.TemporaryDirectory(prefix="ap_") as tmp:
            for idx, info in enumerate(files):
                ext = os.path.splitext(info.filename.lower())[1]
                if ext in INERT_EXT:
                    continue
                if ext not in NESTED_EXT:
                    notes.append(info.filename)
                    continue
                if depth >= MAX_DEPTH or info.file_size > MAX_NESTED_BYTES:
                    notes.append(info.filename + " (not scanned: depth/size)")
                    continue
                try:
                    dest = _extract(zf, info, tmp, idx)
                except ValueError as exc:
                    return "MALICIOUS", "HIGH", "ZIP", f"Archive Policy Violation: {info.filename!r} {exc}"
                status, detail = _scan_nested(dest, ext, depth)
                try:
                    os.remove(dest)
                except OSError:
                    pass
                if status in ("MALICIOUS", "SUSPICIOUS"):
                    return status, ("HIGH" if status == "MALICIOUS" else "MEDIUM"), "ZIP", f"{info.filename}: {detail}"
                if status == "CLEAN":
                    nested_clean += 1
                else:
                    notes.append(f"{info.filename} ({detail})")
        if notes:
            more = f" (+{len(notes) - 5} more)" if len(notes) > 5 else ""
            return "BENIGN", "LOW", "ZIP", "No pickle/code members; unscanned: " + ", ".join(notes[:5]) + more
        if nested_clean:
            return "BENIGN", "MEDIUM", "ZIP", f"No pickle/code members; {nested_clean} nested model file(s) scanned clean"
        return "BENIGN", "HIGH", "ZIP", "ZIP contains only inert files; no pickle or executable members"


def archive_precheck(model_path, filename):
    try:
        if not zipfile.is_zipfile(model_path):
            return None
        out = inspect_zip(model_path)
    except Exception:
        return None  # on any doubt, behave exactly as before
    if out is None:
        return None
    verdict, conf, fmt, summary = out
    return {"model_name": filename, "format": fmt, "verdict": verdict,
            "confidence": conf, "summary": summary, "error": None}
