"""Zero-dependency regression suite for ONNX, GGUF, HDF5, NumPy, and Archive scanners."""
import base64, io, json, marshal, os, struct, tarfile, tempfile
from pathlib import Path
import numpy as np
from model_dispatcher import dispatch, sniff_format
from inspectors.onnx_scanner import scan_onnx
from inspectors.gguf_scanner import scan_gguf
from inspectors.hdf5_scanner import scan_hdf5

def _varint(n: int) -> bytes:
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)

def _ld(fnum: int, data: bytes) -> bytes:
    return _varint((fnum << 3) | 2) + _varint(len(data)) + data

def _make_gguf(tpl=None, tensors=1) -> bytes:
    kv = 1 if tpl is not None else 0
    buf = bytearray(b"GGUF" + struct.pack("<IQQ", 3, tensors, kv))
    if tpl is not None:
        k, v = b"tokenizer.chat_template", tpl.encode()
        buf += struct.pack("<Q", len(k)) + k + struct.pack("<IQ", 8, len(v)) + v
    return bytes(buf)

class _EvilObj:
    def __reduce__(self):
        return (os.system, ("id",))

def run():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        # ONNX
        ok_onnx = d / "ok.onnx"
        bad_op = d / "bad_op.onnx"
        bad_ext = d / "bad_ext.onnx"
        ok_onnx.write_bytes(_varint(8) + _varint(8) + _ld(7, _ld(1, _ld(3, b"n1") + _ld(4, b"MatMul"))))
        bad_op.write_bytes(_varint(8) + _varint(8) + _ld(7, _ld(1, _ld(3, b"n2") + _ld(4, b"PyFunc"))))
        bad_ext.write_bytes(_varint(8) + _varint(8) + _ld(7, _ld(5, _ld(13, _ld(1, b"location") + _ld(2, b"../../etc/passwd")))))
        assert scan_onnx(str(ok_onnx))["verdict"] == "BENIGN"
        assert scan_onnx(str(bad_op))["verdict"] == "MALICIOUS"
        assert scan_onnx(str(bad_ext))["verdict"] == "MALICIOUS"

        # GGUF
        ok_gguf, ssti_gguf, oom_gguf = d / "ok.gguf", d / "ssti.gguf", d / "oom.gguf"
        ok_gguf.write_bytes(_make_gguf("{{ bos_token }}{% for m in messages %}{{ m.content }}{% endfor %}"))
        ssti_gguf.write_bytes(_make_gguf("{{ ''.__class__.__mro__[1].__subclasses__() }}"))
        oom_gguf.write_bytes(_make_gguf(None, tensors=999999999))
        assert scan_gguf(str(ok_gguf))["verdict"] == "BENIGN"
        assert scan_gguf(str(ssti_gguf))["verdict"] == "MALICIOUS"
        assert scan_gguf(str(oom_gguf))["verdict"] == "MALICIOUS"

        # HDF5
        benign_fn = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
        evil_fn = base64.b64encode(marshal.dumps(compile("import os; os.system('id')", "<x>", "exec"))).decode()
        ok_h5, susp_h5, evil_h5 = d / "ok.h5", d / "susp.h5", d / "evil.h5"
        ok_h5.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\x00" * 64)
        susp_h5.write_bytes(b"\x89HDF\r\n\x1a\n" + json.dumps({"class_name": "Lambda", "config": {"name": "l1", "function": [benign_fn]}}).encode())
        evil_h5.write_bytes(b"\x89HDF\r\n\x1a\n" + json.dumps({"class_name": "Lambda", "config": {"name": "l2", "function": [evil_fn]}}).encode())
        assert scan_hdf5(str(ok_h5))["verdict"] == "BENIGN"
        assert scan_hdf5(str(susp_h5))["verdict"] == "SUSPICIOUS"
        assert scan_hdf5(str(evil_h5))["verdict"] == "MALICIOUS"

        # NumPy + Archive
        ok_npy, evil_npy = d / "ok.npy", d / "evil.npy"
        np.save(ok_npy, np.array([1.0, 2.0], dtype=np.float32))
        np.save(evil_npy, np.array([_EvilObj()], dtype=object))
        assert dispatch(str(ok_npy))["verdict"] == "BENIGN"
        assert dispatch(str(evil_npy))["verdict"] == "MALICIOUS"

        slip_tar = d / "slip.tar.gz"
        with tarfile.open(slip_tar, "w:gz") as tf:
            info = tarfile.TarInfo(name="../../etc/evil.txt")
            info.size = 3
            tf.addfile(info, io.BytesIO(b"pwn"))
        assert dispatch(str(slip_tar))["verdict"] == "MALICIOUS"

        z7 = d / "test.7z"
        z7.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
        assert sniff_format(str(z7)) == "7Z"
        assert dispatch(str(z7))["verdict"] == "SUSPICIOUS"

    print("ALL 13 ZERO-DEP BINARY & ARCHIVE TESTS PASSED!")

if __name__ == "__main__":
    run()
