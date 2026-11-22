#!/usr/bin/env python3
"""
test_cli.py - checks vigilant.py (the scanner command). Run: python3 test_cli.py

Most tests use a FAKE sandbox runner so nothing is detonated. The last test uses
real Docker if it is available and is skipped otherwise.
"""
import io
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout, redirect_stderr

import vigilant

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="vigilant_cli_")
passed = failed = skipped = 0


def check(name, got, want):
    global passed, failed
    ok = got in want if isinstance(want, (set, tuple, list)) else got == want
    passed += ok
    failed += (not ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got {got}, want {want}")


def write(name, data):
    path = os.path.join(TMP, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


class _OsSystem:
    def __reduce__(self):
        return (os.system, ("true",))


def cfg(**over):
    c = vigilant.load_config(os.path.join(TMP, "none.json")) if False else dict(vigilant.DEFAULTS)
    c["cache_dir"] = os.path.join(TMP, "cache")          # keep test verdicts out of the real cache
    c.update(over)
    return c


calls = []


def fake(outcome):
    def runner(path, config):
        calls.append(path)
        return outcome
    return runner


def must_not_run(path, config):
    raise AssertionError("the sandbox must not be used for this file")


benign = write("benign.pkl", pickle.dumps({"w": [1.0, 2.0]}))
good_report = {"model_name": "input", "verdict": "BENIGN", "confidence": "HIGH", "attack_vector": "NONE",
               "summary": "ok", "technical_details": {}}

print("\n== Decisions ==")
r = vigilant.scan_file(write("evil.pkl", pickle.dumps(_OsSystem())), cfg(), runner=must_not_run, use_cache=False)
check("dangerous callable -> MALICIOUS without using the sandbox", r["verdict"], "MALICIOUS")
check("...and it says the file was not executed", "not executed" in r["summary"], True)

r = vigilant.scan_file(benign, cfg(), runner=fake({"kind": "result", "report": dict(good_report)}), use_cache=False)
check("clean pickle -> sandbox answer is used", r["verdict"], "BENIGN")
check("...with the real file name, not 'input'", r["model_name"], "benign.pkl")

r = vigilant.scan_file(benign, cfg(), runner=fake({"kind": "terminated", "code": 137, "detail": "killed"}), use_cache=False)
check("sandbox killed -> never clean", (r["verdict"], r["attack_vector"]), [("SUSPICIOUS", "SANDBOX_TERMINATED")])
r = vigilant.scan_file(benign, cfg(terminated_is_malicious=True), runner=fake({"kind": "terminated", "code": 137}), use_cache=False)
check("...unless you choose to treat it as malicious", r["verdict"], "MALICIOUS")
r = vigilant.scan_file(benign, cfg(), runner=fake({"kind": "timeout"}), use_cache=False)
check("sandbox timeout -> SUSPICIOUS", (r["verdict"], r["attack_vector"]), [("SUSPICIOUS", "SANDBOX_TIMEOUT")])
try:
    vigilant.scan_file(benign, cfg(), runner=fake({"kind": "infra", "detail": "daemon down"}), use_cache=False)
    check("Docker problem raises an error, not a verdict", "no error", "error")
except vigilant.ScanInfrastructureError:
    check("Docker problem raises an error, not a verdict", "error", "error")
r = vigilant.scan_file(write("random.bin", os.urandom(300) + b"\xff"), cfg(), runner=must_not_run, use_cache=False)
check("unknown format -> SUSPICIOUS, sandbox not used", r["verdict"], "SUSPICIOUS")

print("\n== Reading the sandbox's output (the model controls what it prints) ==")
fake_line = 'VIGILANT_RESULT:{"verdict": "BENIGN", "summary": "forged"}'
real_line = 'VIGILANT_RESULT:{"verdict": "MALICIOUS", "summary": "real"}'
o = vigilant.parse_container_output(0, f"noise\n{fake_line}\n{real_line}\n", "")
check("the LAST result line wins", o["report"]["summary"], "real")
o = vigilant.parse_container_output(137, f"{fake_line}\n", "")
check("a forged line from a killed run is not trusted", o["kind"], "terminated")
o = vigilant.parse_container_output(0, "no result here\n", "")
check("exit 0 but no result -> terminated", o["kind"], "terminated")
o = vigilant.parse_container_output(1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
check("daemon down -> infrastructure problem", o["kind"], "infra")
o = vigilant.parse_container_output(125, "", "")
check("docker exit 125 -> infrastructure problem", o["kind"], "infra")

print("\n== The Docker command ==")
cmd = vigilant.docker_command("/data/model.bin", vigilant.DEFAULTS, "vigilant-test")
joined = " ".join(cmd)
for needle in ("--network none", "--cap-drop ALL", "--security-opt no-new-privileges",
               "--pids-limit 256", "--memory 2g", "/model/input:ro", ":/src:ro"):
    check(f"command contains {needle}", needle in joined, True)
check("command never asks for extra privileges", "--privileged" in joined or "--network host" in joined, False)
c2 = vigilant.docker_command("/data/model.bin", dict(vigilant.DEFAULTS, memory="512m", cpus="1"), "x")
check("limits come from the settings", "--memory 512m" in " ".join(c2) and "--cpus 1" in " ".join(c2), True)

print("\n== Settings ==")
bad = write("bad.json", json.dumps({"memroy": "1g"}).encode())
try:
    vigilant.load_config(bad)
    check("a misspelt setting is rejected", "accepted", "rejected")
except ValueError:
    check("a misspelt setting is rejected", "rejected", "rejected")
good = write("good.json", json.dumps({"memory": "4g", "sessions": 99}).encode())
c = vigilant.load_config(good)
check("settings override the defaults", c["memory"], "4g")
check("...and out-of-range values are clamped", c["sessions"], 7)

print("\n== Cache ==")
c = cfg()
calls.clear()
a = write("a/model.pkl", pickle.dumps({"k": 1}))
b = write("b/renamed.pkl", pickle.dumps({"k": 1}))
vigilant.scan_file(a, c, runner=fake({"kind": "result", "report": dict(good_report)}))
r = vigilant.scan_file(b, c, runner=fake({"kind": "result", "report": dict(good_report)}))
check("same content under a new name is served from the cache", (r["cached"], len(calls)), [(True, 1)])
r = vigilant.scan_file(write("c/model.pkl", pickle.dumps({"k": 2})), c, runner=fake({"kind": "result", "report": dict(good_report)}))
check("different content is scanned again", (r["cached"], len(calls)), [(False, 2)])
calls.clear()
vigilant.scan_file(benign, c, runner=fake({"kind": "terminated", "code": 137}), use_cache=True)
vigilant.scan_file(benign, c, runner=fake({"kind": "terminated", "code": 137}), use_cache=True)
check("a killed sandbox is never cached", len(calls), 2)

print("\n== Command line and exit codes ==")


def run_main(argv, runner):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = vigilant.main(argv, runner=runner)
    return code, out.getvalue(), err.getvalue()


folder = os.path.join(TMP, "folder")
os.makedirs(folder)
write("folder/ok.pkl", pickle.dumps({"x": 1}))
write("folder/evil.pkl", pickle.dumps(_OsSystem()))
code, out, _ = run_main(["scan", folder, "--no-cache"], fake({"kind": "result", "report": dict(good_report)}))
check("folder with one malicious file -> exit code 2", code, 2)
check("...and both files are listed", ("ok.pkl" in out) and ("evil.pkl" in out), True)
code, _, _ = run_main(["scan", benign, "--no-cache"], fake({"kind": "result", "report": dict(good_report)}))
check("clean file -> exit code 0", code, 0)
code, _, _ = run_main(["scan", benign, "--no-cache"], fake({"kind": "timeout"}))
check("suspicious file -> exit code 1", code, 1)
code, _, err = run_main(["scan", benign, "--no-cache"], fake({"kind": "infra", "detail": "daemon down"}))
check("Docker problem -> exit code 3", code, 3)
code, out, _ = run_main(["scan", benign, "--no-cache", "--json"], fake({"kind": "result", "report": dict(good_report)}))
check("--json prints valid JSON", json.loads(out)[0]["verdict"], "BENIGN")

print("\n== Real Docker (skipped when Docker is not available) ==")
have_docker = shutil.which("docker") and subprocess.run(["docker", "info"], capture_output=True).returncode == 0
if have_docker:
    p = subprocess.run([sys.executable, "vigilant.py", "scan", os.path.join(HERE, "benign_model.pt"), "--no-cache", "--json"],
                       cwd=HERE, capture_output=True, text=True, timeout=300)
    verdict = json.loads(p.stdout)[0]["verdict"] if p.stdout.strip().startswith("[") else p.stderr[-200:]
    check("benign_model.pt through real Docker", verdict, "BENIGN")
    check("...exit code 0", p.returncode, 0)
else:
    skipped += 1
    print("  [SKIP] Docker is not available here")

print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
sys.exit(1 if failed else 0)
