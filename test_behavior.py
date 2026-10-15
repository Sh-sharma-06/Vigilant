#!/usr/bin/env python3
"""
test_behavior.py - checks the "human behaviour" simulation (behavior_sim.py).

SAFETY: every payload here only calls `true`, `/bin/true`, sys.exit(0) or
os._exit(0). The sandbox blocks all of them. Run: python3 test_behavior.py
"""
import datetime
import functools
import json
import os
import pickle
import subprocess
import sys
import tempfile
import textwrap
import time

import behavior_sim

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="vigilant_behavior_")
passed = failed = 0


def check(name, got, want):
    global passed, failed
    ok = got in want if isinstance(want, (set, tuple, list)) else got == want
    passed += ok
    failed += (not ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got {got}, want {want}")


def write(name, data, mode="wb"):
    path = os.path.join(TMP, name)
    with open(path, mode) as f:
        f.write(data)
    return path


def run_vigilant(path, *flags, env=None):
    e = dict(os.environ)
    e["PYTHONPATH"] = TMP + os.pathsep + e.get("PYTHONPATH", "")
    e.update(env or {})
    out = subprocess.run([sys.executable, "vigilant_one.py", path, "--no-cache", *flags],
                         cwd=HERE, capture_output=True, text=True, timeout=300, env=e).stdout
    for line in out.splitlines():
        if line.startswith("VIGILANT_RESULT:"):
            return json.loads(line.split(":", 1)[1])
    return {"verdict": "NO_RESULT", "stdout": out[-300:]}


print("\n== The simulated clock (in-process, nothing is loaded) ==")
real_before = time.time()
with behavior_sim.warped(365):
    shifted = time.time() - real_before
    check("time.time() is about one year ahead", 364 * 86400 < shifted < 366 * 86400, True)
    year_gap = datetime.datetime.now().year - datetime.datetime.fromtimestamp(real_before).year
    check("datetime.now() moves with it", year_gap in (0, 1) and datetime.datetime.now() > datetime.datetime.fromtimestamp(real_before) + datetime.timedelta(days=364), True)
    t0 = time.time()
    wall = time.monotonic()
    time.sleep(100000)                                  # would be 27 hours
    check("time.sleep(100000) returns at once", time.monotonic() - wall < 1.0, True)
    check("...and the clock jumped forward by that much", time.time() - t0 >= 100000, True)
    import socket
    check("believable host name", socket.gethostname(), behavior_sim.FAKE_HOST)
check("clock is restored afterwards", abs(time.time() - real_before) < 5, True)
check("datetime is restored afterwards", datetime.datetime.__module__, "datetime")

print("\n== A time bomb that only fires about 200 days from now ==")
trigger = datetime.datetime.now() + datetime.timedelta(days=200)
write("tb_mod.py", textwrap.dedent(f"""
    import datetime, os
    TRIGGER = datetime.datetime({trigger.year}, {trigger.month}, {trigger.day})
    class Bomb:
        def __call__(self, *args, **kwargs):
            if datetime.datetime.now() >= TRIGGER:
                os.system("true")          # harmless, and blocked by the sandbox anyway
            return 0
"""), "w")
sys.path.insert(0, TMP)
import tb_mod
bomb = write("timebomb.pkl", pickle.dumps(tb_mod.Bomb()))
r = run_vigilant(bomb)
check("found with the simulated dates", r["verdict"], "MALICIOUS")
check("...as a process-exec attempt", r.get("attack_vector"), "PROCESS_EXEC")
r = run_vigilant(bomb, env={"VIGILANT_SESSIONS": "1"})
check("control: today-only run does NOT see it", r["verdict"] != "MALICIOUS", True)

print("\n== Exit attempts can no longer hide a payload (static pass OFF) ==")


class _ExitAtLoad:
    def __reduce__(self):
        return (sys.exit, (0,))


class _OsExitAtLoad:
    def __reduce__(self):
        return (os._exit, (0,))


cases = {
    "sys.exit while loading": pickle.dumps(_ExitAtLoad()),
    "os._exit while loading": pickle.dumps(_OsExitAtLoad()),
    "sys.exit when the model is used": pickle.dumps(functools.partial(sys.exit, 0)),
    "os._exit when the model is used": pickle.dumps(functools.partial(os._exit, 0)),
}
for name, data in cases.items():
    r = run_vigilant(write(name.replace(" ", "_").replace(".", "") + ".pkl", data), "--no-static")
    check(f"{name} -> verdict", r["verdict"], "MALICIOUS")
    check(f"{name} -> vector", r.get("attack_vector"), "ANTI_SANDBOX_EXIT")

print("\n== Ordinary files are not disturbed ==")
r = run_vigilant(os.path.join(HERE, "benign_model.pt"))
check("benign_model.pt stays BENIGN", r["verdict"], "BENIGN")
sessions = r.get("technical_details", {}).get("behavior_sessions", [])
check("...and ran in every simulated session", len(sessions), len(behavior_sim.SESSION_OFFSETS_DAYS))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
