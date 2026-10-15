#!/usr/bin/env python3
"""
test_policy.py - checks Step 1 (static pass + honeypot escalation + cache key).

SAFETY: this script only WRITES pickle files and scans them. Static tests never
load a pickle. The dynamic tests run `vigilant_one.py` in a child process; the
only commands inside them are `true` and `/bin/true`, which do nothing, and the
audit hook blocks them anyway.  Still: run it inside Docker or a VM if you can.

Run:  python3 test_policy.py
"""
import functools
import json
import os
import pickle
import subprocess
import sys
import tempfile

import struct
import zipfile

from verdict_policy import apply_policy, classify_target, static_verdict
from model_dispatcher import sniff_format

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="vigilant_test_")
passed = failed = 0


def check(name, got, want):
    global passed, failed
    ok = got in want if isinstance(want, (set, tuple, list)) else got == want
    passed += ok
    failed += (not ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got {got}, want {want}")


def write(name, data):
    path = os.path.join(TMP, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


class _OsSystem:
    def __reduce__(self):
        return (os.system, ("true",))


# ---------------------------------------------------------------- static ----
print("\n== Static pass (nothing is executed) ==")
check("benign dict", static_verdict(write("benign.pkl", pickle.dumps({"w": [1.0, 2.0]})))["verdict"], "BENIGN")

for proto in (0, 1, 2, 3, 4, 5):
    p = write(f"os_system_p{proto}.pkl", pickle.dumps(_OsSystem(), protocol=proto))
    check(f"os.system, protocol {proto}", static_verdict(p)["verdict"], "MALICIOUS")

# old-style INST opcode: module + name + immediate call (was a scanner bypass)
check("INST opcode (os system)", static_verdict(write("inst.pkl", b"(S'true'\nios\nsystem\n."))["verdict"], "MALICIOUS")

# STACK_GLOBAL whose strings come from the memo, with decoy strings pushed last
memo_pickle = (b"\x80\x04"
               b"\x8c\x02os\x94" b"0"            # push 'os', memoize as 0, pop
               b"\x8c\x06system\x94" b"0"        # push 'system', memoize as 1, pop
               b"\x8c\x06decoy1" b"\x8c\x06decoy2" b"00"   # decoys, popped
               b"h\x00h\x01\x93"                 # BINGET 0, BINGET 1, STACK_GLOBAL
               b"\x8c\x04true\x85R.")
check("memoized STACK_GLOBAL", static_verdict(write("memo.pkl", memo_pickle))["verdict"], "MALICIOUS")

# payload first, then garbage: findings before the parse error must survive
broken = pickle.dumps(_OsSystem(), protocol=2)[:-1] + b"\xff\xff"
check("payload then invalid bytes", static_verdict(write("broken.pkl", broken))["verdict"], "MALICIOUS")

check("unknown custom class", static_verdict(write("custom.pkl", b"cmy_company.models\nSecretNet\n)\x81."))["verdict"], "SUSPICIOUS")
check("known ML library class", static_verdict(write("sk.pkl", b"csklearn.linear_model._base\nLinearRegression\n)\x81."))["verdict"], "BENIGN")
check("numpy runstring gadget", classify_target("numpy.testing._private.utils.runstring"), "dangerous")
check("builtins.eval", classify_target("builtins.eval"), "dangerous")
check("builtins.set", classify_target("builtins.set"), "known")


# ---- v2: evasions found in the public benchmark ----
print("\n== Static pass v2 (evasions) ==")
two = pickle.dumps({"a": 1}) + pickle.dumps(_OsSystem())
check("payload in the SECOND pickle of a file", static_verdict(write("two_streams.pkl", two))["verdict"], "MALICIOUS")
check("benign pickle + raw trailing bytes", static_verdict(write("trailing.pkl", pickle.dumps({"w": 1}) + bytes(range(1, 40))))["verdict"], "BENIGN")

p0 = write("p0.pkl", pickle.dumps(_OsSystem(), protocol=0))
check("protocol-0 file is detected as a pickle", sniff_format(p0), "PICKLE")
broken0 = pickle.dumps(_OsSystem(), protocol=0)[:-1] + b"\xff\xff"      # no 0x80 header, bad tail
check("damaged protocol-0 file is an unknown container", sniff_format(write("trunc.pkl", broken0)), "UNKNOWN")


def make_zip(name, member, payload, flip_flag=False, rename_local=None):
    path = os.path.join(TMP, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(member, payload)
    raw = bytearray(open(path, "rb").read())
    if flip_flag:                                   # set bit 0 (encrypted) in local + central header
        raw[6] |= 1
        cd = raw.rfind(b"PK\x01\x02")
        raw[cd + 8] |= 1
    if rename_local:                                # local header name differs from central directory
        i = raw.find(member.encode())
        raw[i:i + len(rename_local)] = rename_local.encode()
    open(path, "wb").write(bytes(raw))
    return path


evil = pickle.dumps(_OsSystem(), protocol=2)
check("zip member flagged 'encrypted' but readable", static_verdict(make_zip("flag.zip", "m/data.pkl", evil, flip_flag=True))["verdict"], "MALICIOUS")
check("zip pickle named data.txt", static_verdict(make_zip("txt.zip", "data.txt", evil))["verdict"], "MALICIOUS")
check("zip local/central name mismatch", static_verdict(make_zip("name.zip", "data.pkl", evil, rename_local="data.xyz"))["verdict"], "MALICIOUS")
good = make_zip("good.zip", "archive/data.pkl", pickle.dumps({"w": [1.0]}))
with zipfile.ZipFile(good, "a") as z:
    z.writestr("archive/data/0", b"\x80\x03" + bytes(range(7, 120)))   # tensor-like bytes that start 0x80
check("benign zip with a tensor blob starting 0x80", static_verdict(good)["verdict"], "BENIGN")

for tgt in ("requests.api.get", "httplib.HTTPSConnection", "torch._inductor.codecache.compile_file",
            "torch.serialization.load", "functools.partial", "aiohttp.client.ClientSession"):
    check(f"denylist: {tgt}", classify_target(tgt), "dangerous")
check("allowed: torch._utils._rebuild_tensor_v2", classify_target("torch._utils._rebuild_tensor_v2"), "known")

crashed = {"verdict": "MALICIOUS", "confidence": "HIGH", "attack_vector": "CORRUPT_OR_EXPLOIT", "summary": "boom",
           "technical_details": {}}
quiet = {"verdict": "BENIGN", "attack_vector": "NONE", "summary": ""}
check("bare load failure is only SUSPICIOUS", apply_policy(dict(crashed), None, quiet)["verdict"], "SUSPICIOUS")
check("load failure + static MALICIOUS stays MALICIOUS",
      apply_policy(dict(crashed), {"verdict": "MALICIOUS", "attack_vector": "X", "summary": "s"}, quiet)["verdict"], "MALICIOUS")

# --------------------------------------------------------------- dynamic ----
print("\n== Dynamic escalation (static OFF, so only the honeypot can catch these) ==")


def run_vigilant(path, *flags):
    out = subprocess.run([sys.executable, "vigilant_one.py", path, "--no-cache", *flags],
                         cwd=HERE, capture_output=True, text=True, timeout=120).stdout
    for line in out.splitlines():
        if line.startswith("VIGILANT_RESULT:"):
            return json.loads(line.split(":", 1)[1])
    return {"verdict": "NO_RESULT", "stdout": out[-300:]}


# These objects only call os.system / posix_spawn when the FUZZER calls them,
# so the old code (which swallowed the blocked call) said BENIGN.
r = run_vigilant(write("partial_system.pkl", pickle.dumps(functools.partial(os.system, "true"))), "--no-static")
check("fuzz-time os.system -> verdict", r["verdict"], "MALICIOUS")
check("fuzz-time os.system -> vector", r.get("attack_vector"), "PROCESS_EXEC")

r = run_vigilant(write("partial_spawn.pkl", pickle.dumps(functools.partial(os.posix_spawn, "/bin/true", ["true"], {}))), "--no-static")
check("fuzz-time posix_spawn -> verdict", r["verdict"], "MALICIOUS")

print("\n== End to end (static ON) ==")
r = run_vigilant(write("os_system.pkl", pickle.dumps(_OsSystem())))
check("os.system -> verdict", r["verdict"], "MALICIOUS")
check("os.system -> decided by static, file never run", r["technical_details"].get("decided_by"), "static")
r = run_vigilant(p0)
check("protocol-0 os.system end to end", r["verdict"], "MALICIOUS")
check("protocol-0: decided by static", r["technical_details"].get("decided_by"), "static")
r = run_vigilant(write("trunc2.pkl", broken0))
check("damaged protocol-0 payload end to end (unknown-container fallback)", r["verdict"], "MALICIOUS")
r = run_vigilant(write("trunc3.pkl", broken))
check("damaged protocol-2 payload end to end", r["verdict"], "MALICIOUS")
r = run_vigilant(os.path.join(HERE, "benign_model.pt"))
check("benign_model.pt", r["verdict"], "BENIGN")
r = run_vigilant(os.path.join(HERE, "canary_model.pt"))
check("canary_model.pt (custom class)", r["verdict"], {"SUSPICIOUS", "MALICIOUS"})

# ----------------------------------------------------------------- cache ----
print("\n== Cache key is content, not file name ==")
a = write("same_name_a.pkl", pickle.dumps({"w": 1}))
sub = os.path.join(TMP, "sub"); os.makedirs(sub)
b = os.path.join(sub, "same_name_a.pkl")
with open(b, "wb") as f:
    f.write(pickle.dumps(_OsSystem()))
subprocess.run([sys.executable, "vigilant_one.py", a], cwd=HERE, capture_output=True, timeout=120)  # caches BENIGN
out = subprocess.run([sys.executable, "vigilant_one.py", b], cwd=HERE, capture_output=True, text=True, timeout=120).stdout
verdict = [json.loads(l.split(":", 1)[1]) for l in out.splitlines() if l.startswith("VIGILANT_RESULT:")][0]["verdict"]
check("malicious file re-using a benign file's name", verdict, "MALICIOUS")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
