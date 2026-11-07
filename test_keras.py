"""test_keras.py - builds tiny fixtures, runs the Keras scanner. Run: python test_keras.py"""
import base64, io, json, marshal, os, tempfile, zipfile
from inspectors.keras_scanner import scan_keras_v3, classify_zip

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n" + b"\0" * 64

def weights_bytes(size=0):
    try:
        import h5py, numpy as np
    except ImportError:
        return HDF5_MAGIC + os.urandom(size)
    bio = io.BytesIO()
    with h5py.File(bio, "w") as h:
        h.create_dataset("layers/dense/vars/0", data=np.random.rand(4, 4).astype("float32"))
        if size:
            h.create_dataset("layers/big", data=np.frombuffer(os.urandom(size), dtype="uint8"))
    return bio.getvalue()

def weights_with_link():
    import h5py
    bio = io.BytesIO()
    with h5py.File(bio, "w") as h:
        h["x"] = h5py.ExternalLink("/etc/passwd", "/")
    return bio.getvalue()

def make(path, config, extra=None, big_weights=0, weights=None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("config.json", json.dumps(config))
        z.writestr("metadata.json", json.dumps({"keras_version": "3.0"}))
        z.writestr("model.weights.h5", weights if weights is not None else weights_bytes(big_weights))
        for n, d in (extra or {}).items():
            z.writestr(n, d)

def lam(src):
    code = compile(src, "<lambda>", "eval")
    return {"class_name": "Lambda", "module": "keras.layers", "config": {
        "function": {"class_name": "__lambda__", "config": {
            "code": base64.b64encode(marshal.dumps(code)).decode()}}}}

CLEAN = {"class_name": "Sequential", "module": "keras", "config": {"layers": [
    {"class_name": "Dense", "module": "keras.layers", "config": {"units": 4}}]}}
def with_layer(l): return {"class_name": "Sequential", "module": "keras", "config": {"layers": [l]}}

d = tempfile.mkdtemp()
cases = [
    ("clean",           lambda p: make(p, CLEAN), "CLEAN"),
    ("clean_big_weights", lambda p: make(p, CLEAN, big_weights=8_000_000), "CLEAN"),
    ("harmless_lambda", lambda p: make(p, with_layer(lam("lambda x: x * 2"))), "SUSPICIOUS"),
    ("evil_lambda",     lambda p: make(p, with_layer(lam("__import__('os').system('calc')"))), "MALICIOUS"),
    ("bad_module",      lambda p: make(p, with_layer({"class_name": "X", "module": "evilpkg.mod", "config": {}})), "SUSPICIOUS"),
    ("custom_registered", lambda p: make(p, with_layer({"class_name": "X", "module": "keras.layers", "registered_name": "Custom>X", "config": {}})), "SUSPICIOUS"),
    ("traversal",       lambda p: make(p, CLEAN, extra={"../../evil.txt": "x"}), "MALICIOUS"),
    ("hidden_pickle",   lambda p: make(p, CLEAN, extra={"payload.pkl": b"x"}), "SUSPICIOUS"),
]
try:
    import h5py
    cases.append(("weights_ext_link", lambda p: make(p, CLEAN, weights=weights_with_link()), "MALICIOUS"))
except ImportError:
    print("(h5py not installed: weights checks skipped)")
ok = True
for name, build, want in cases:
    p = os.path.join(d, name + ".keras"); build(p)
    r = scan_keras_v3(p)
    good = r["verdict"] == want and classify_zip(p) == "KERAS_V3"
    ok &= good
    print(f"{'PASS' if good else 'FAIL'}  {name:20s} got={r['verdict']:10s} want={want:10s} | {r['reason'][:70]}")
pt = os.path.join(d, "t.pt")
with zipfile.ZipFile(pt, "w") as z: z.writestr("archive/data.pkl", b"x")
print("PASS" if classify_zip(pt) == "PYTORCH_ZIP" else "FAIL", " pytorch zip still routed to PYTORCH_ZIP")
print("ALL PASSED" if ok else "SOME FAILED")