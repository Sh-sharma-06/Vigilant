"""Scan one model file and print VIGILANT_RESULT:<json> (used by benchmark_harness.py).

  python vigilant_one.py model.pt              normal run (uses the cache)
  python vigilant_one.py model.pt --no-cache   ignore and do not write the cache
  python vigilant_one.py model.pt --no-static  skip the static pass (tests only)
"""
import hashlib
import json
import os
import sys

import model_dispatcher
import sandbox_runner  # NOTE: this import replaces sys.exit/os._exit, so use `raise SystemExit` below
from verdict_policy import POLICY_VERSION


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


args = [a for a in sys.argv[1:] if not a.startswith("--")]
if not args:
    raise SystemExit(__doc__)
p = args[0]
no_cache = "--no-cache" in sys.argv
static_first = "--no-static" not in sys.argv

# Cache key = file CONTENT hash + policy version, never the file name.
os.makedirs("vigilant_cache", exist_ok=True)
cf = os.path.join("vigilant_cache", f"{sha256_of(p)}.v{POLICY_VERSION}.json")
if not no_cache and static_first and os.path.exists(cf):
    print("VIGILANT_RESULT:" + open(cf).read())
    raise SystemExit(0)

r = model_dispatcher.dispatch(p, sandbox_runner=sandbox_runner.run_sandbox,
                              static_first=static_first)
s = json.dumps(r, default=str)
if not no_cache and static_first:
    open(cf, "w").write(s)
print("VIGILANT_RESULT:" + s)
