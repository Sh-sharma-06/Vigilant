#!/usr/bin/env python3
"""
Regression test on REAL binary .gguf and .onnx files on disk.
Verifies:
  1. A benign GGUF file whose binary token table contains "{% AI %}" and "\x07\x05" bytes
     after a clean chat_template is NEVER flagged as MALICIOUS.
  2. A malicious GGUF file with CVE-2024-34359 SSTI (__subclasses__) IS flagged as MALICIOUS.
  3. A benign ONNX model with com.microsoft::MatMulNBits and com.microsoft::RotaryEmbedding is BENIGN.
  4. A malicious ONNX model with external tensor path traversal (../../etc/passwd) IS flagged as MALICIOUS.
"""
import struct
import tempfile
from pathlib import Path
import onnx
from onnx import helper, TensorProto
from inspectors.multi_format_scanner import scan_gguf, scan_onnx

def pack_gguf_string(s: bytes) -> bytes:
    return struct.pack("<Q", len(s)) + s

def build_test_gguf(path: Path, chat_template: str, trailing_binary_noise: bytes):
    with open(path, "wb") as f:
        f.write(b"GGUF")
        # version=3, tensor_count=1, kv_count=2
        f.write(struct.pack("<IQQ", 3, 1, 2))
        # KV 1: tokenizer.chat_template (STRING = 8)
        f.write(pack_gguf_string(b"tokenizer.chat_template"))
        f.write(struct.pack("<I", 8))
        f.write(pack_gguf_string(chat_template.encode("utf-8")))
        # KV 2: tokenizer.ggml.tokens (ARRAY = 9 of STRING = 8) containing binary bytes + "{% AI %}"
        f.write(pack_gguf_string(b"tokenizer.ggml.tokens"))
        f.write(struct.pack("<IQ", 9, 8, 1) if False else struct.pack("<I", 9) + struct.pack("<IQ", 8, 1))
        f.write(pack_gguf_string(trailing_binary_noise))
        f.write(b"\x00" * 64)

with tempfile.TemporaryDirectory() as tmp:
    tmp_dir = Path(tmp)

    # 1. Benign GGUF with binary token noise that previously crashed Jinja2 at byte offset
    benign_gguf = tmp_dir / "benign_qwen_imatrix.gguf"
    build_test_gguf(
        benign_gguf,
        chat_template="{% for message in messages %}{{ message['content'] }}{% endfor %}",
        trailing_binary_noise=b"\x07\x05\x04{% unknown_tag_AI %}{{ broken_token \x07"
    )
    res_b_gguf = scan_gguf(str(benign_gguf))
    assert not res_b_gguf["is_malicious"], f"Regression failure: benign GGUF flagged: {res_b_gguf}"
    print("[PASS] 1/4 Benign GGUF with binary token noise -> is_malicious=False")

    # 2. Malicious GGUF with SSTI (__subclasses__)
    mal_gguf = tmp_dir / "malicious_ssti.gguf"
    build_test_gguf(
        mal_gguf,
        chat_template="{{ ''.__class__.__mro__[1].__subclasses__()[133]('id', shell=True) }}",
        trailing_binary_noise=b"normal_token"
    )
    res_m_gguf = scan_gguf(str(mal_gguf))
    assert res_m_gguf["is_malicious"], f"Regression failure: missed GGUF SSTI: {res_m_gguf}"
    print("[PASS] 2/4 Malicious GGUF SSTI -> is_malicious=True")

    # 3. Benign ONNX with com.microsoft::MatMulNBits & RotaryEmbedding
    benign_onnx = tmp_dir / "benign_phi3_microsoft.onnx"
    node1 = helper.make_node("MatMulNBits", ["X", "W"], ["Y"], domain="com.microsoft")
    node2 = helper.make_node("RotaryEmbedding", ["Y"], ["Z"], domain="com.microsoft")
    graph = helper.make_graph([node1, node2], "phi3_graph", [], [])
    opset = [helper.make_opsetid("", 18), helper.make_opsetid("com.microsoft", 1)]
    model = helper.make_model(graph, opset_imports=opset)
    onnx.save(model, str(benign_onnx))
    res_b_onnx = scan_onnx(str(benign_onnx))
    assert not res_b_onnx["is_malicious"], f"Regression failure: benign com.microsoft ONNX flagged: {res_b_onnx}"
    print("[PASS] 3/4 Benign ONNX (com.microsoft::MatMulNBits/RotaryEmbedding) -> is_malicious=False")

    # 4. Malicious ONNX with CVE-2024-27318 path traversal
    mal_onnx = tmp_dir / "malicious_traversal.onnx"
    ext_tensor = helper.make_tensor("mal_weight", TensorProto.FLOAT, [1], [1.0])
    ext_tensor.data_location = TensorProto.EXTERNAL
    entry = ext_tensor.external_data.add()
    entry.key = "location"
    entry.value = "../../etc/passwd"
    mal_graph = helper.make_graph([], "mal_graph", [], [], initializer=[ext_tensor])
    onnx.save(helper.make_model(mal_graph), str(mal_onnx))
    res_m_onnx = scan_onnx(str(mal_onnx))
    assert res_m_onnx["is_malicious"], f"Regression failure: missed ONNX traversal: {res_m_onnx}"
    print("[PASS] 4/4 Malicious ONNX Path Traversal -> is_malicious=True\n")
    print("ALL 4 REAL BINARY REGRESSION TESTS PASSED!")
