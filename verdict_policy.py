"""
verdict_policy.py - the one place that decides Vigilant's final verdict.

Three jobs:
  1. static_verdict(path)   run pickle_scanner (never executes the file) and
                            sort every finding into dangerous / known / unknown.
  2. escalate(telemetry)    turn blocked process / network / recon events from
                            the honeypot into a verdict.
  3. apply_policy(...)      final verdict = the WORST of static, sandbox and
                            honeypot. A quiet sandbox can no longer overrule a
                            dangerous static finding or a blocked syscall.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pickle_scanner

# Bump when rules change; vigilant_one.py puts it in the cache file name so old
# cached verdicts are never reused after a policy change.
POLICY_VERSION = "4"

RANK = {"BENIGN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

# --- what counts as "dangerous" -------------------------------------------
# Whole modules: importing a callable from these during unpickling is never
# needed by a real model checkpoint.
DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty",
    "runpy", "importlib", "marshal", "ctypes", "webbrowser", "http", "urllib",
    "asyncio", "code", "codeop", "pickle", "_pickle", "dill", "cloudpickle",
    "multiprocessing", "threading", "signal", "ftplib", "smtplib", "telnetlib",
    "socketserver", "xmlrpc", "ssl", "select", "pdb", "bdb", "cProfile",
    "profile", "timeit", "platform", "commands", "popen2", "pip", "zipimport",
    "site", "pydoc", "venv", "ensurepip", "tempfile", "glob",
    # network / HTTP clients (a model file has no reason to import these)
    "aiohttp", "httplib", "requests", "urllib2", "urllib3",
    # more code-execution helpers
    "trace", "doctest", "imaplib", "distutils", "idlelib", "lib2to3", "test",
    "_operator", "_osx_support", "_aix_support", "_pyrepl", "uuid", "cloudpickle",
}
# builtins that execute code, reach attributes, or touch files
DANGEROUS_BUILTINS = {
    "eval", "exec", "compile", "open", "__import__", "getattr", "setattr",
    "delattr", "globals", "locals", "vars", "input", "breakpoint",
}
# Specific gadgets inside otherwise normal libraries
DANGEROUS_PREFIXES = (
    "operator.attrgetter", "operator.methodcaller", "operator.itemgetter",
    "functools.partial", "logging.FileHandler", "_io.FileIO", "pkgutil.resolve_name",
    "torch._inductor", "torch._dynamo", "torch.fx.experimental",
    "torch.jit.unsupported_tensor_ops", "torch.serialization",
    "torch.utils._config_module", "torch.utils.collect_env",
    "torch.utils.data.datapipes.utils.decoder",
    "numpy.testing._private.utils", "numpy.f2py",
    "torch.hub", "torch.utils.bottleneck", "torch.utils.data._utils.worker",
    "functools.reduce", "types.FunctionType", "types.CodeType", "types.MethodType",
)
# Libraries that legitimately appear in model pickles. This does NOT make a
# file safe; it only means "an unlisted class from here is not suspicious by
# itself". Dangerous rules above are checked first. Tune it using the false
# positives that show up in your benchmark.
KNOWN_ML_ROOTS = {
    "numpy", "scipy", "pandas", "sklearn", "xgboost", "lightgbm", "joblib",
    "torch", "transformers", "collections", "copyreg", "_codecs", "datetime",
    "decimal", "fractions", "re", "argparse", "enum", "dataclasses",
    "typing", "functools", "itertools",
}


def classify_target(target: str) -> str:
    """Return 'dangerous', 'known' or 'unknown' for a 'module.name' target."""
    if not target or target == "UNKNOWN":
        return "unknown"
    root, _, rest = target.partition(".")
    if root in ("builtins", "__builtin__"):
        return "dangerous" if rest.split(".")[0] in DANGEROUS_BUILTINS else "known"
    if root in DANGEROUS_MODULES:
        return "dangerous"
    if any(target.startswith(p) for p in DANGEROUS_PREFIXES):
        return "dangerous"
    if root in KNOWN_ML_ROOTS:
        return "known"
    return "unknown"


def _result(verdict: str, vector: str, summary: str, **extra: Any) -> Dict[str, Any]:
    return {"verdict": verdict, "attack_vector": vector, "summary": summary, **extra}


def static_verdict(path: str) -> Dict[str, Any]:
    """Static pass. Reads opcodes only; the file is never unpickled."""
    try:
        scan = pickle_scanner.scan_file(Path(path))
    except Exception as exc:                      # fail closed, never crash the pipeline
        return _result("SUSPICIOUS", "STATIC_ERROR",
                       f"static scan crashed: {type(exc).__name__}: {exc}", evidence=[])
    kind = scan.get("verdict")

    if kind == "error":
        return _result("SUSPICIOUS", "STATIC_ERROR",
                       f"static scan could not read pickle data: {scan.get('error')}",
                       evidence=[])
    findings: List[dict] = [f for s in scan.get("streams", [])
                            for f in s.get("findings", [])]
    dangerous = sorted({f["target"] for f in findings
                        if classify_target(f["target"]) == "dangerous"})
    unknown = sorted({f["target"] for f in findings
                      if classify_target(f["target"]) == "unknown"})

    if dangerous:
        return _result("MALICIOUS", "DANGEROUS_GLOBAL",
                       "static scan found dangerous callable(s): "
                       + ", ".join(dangerous[:5]), evidence=dangerous[:10])
    if unknown:
        return _result("SUSPICIOUS", "UNKNOWN_GLOBAL",
                       "static scan found unreviewed class(es): "
                       + ", ".join(unknown[:5]), evidence=unknown[:10])
    if kind == "unparseable":
        return _result("SUSPICIOUS", "UNPARSEABLE",
                       "pickle stream could not be parsed", evidence=[])
    return _result("BENIGN", "NONE", "static scan found nothing risky", evidence=[])


# --- honeypot telemetry -> verdict ----------------------------------------
_PROCESS = {"AUDIT_PROCESS"}
_NETWORK = {"SOCKET_CONNECT", "AUDIT_NETWORK", "URLLIB_OPEN", "HTTP_REQUEST"}
_RECON = {"RECON_FILE_INTERCEPT", "RECON_ENV_INTERCEPT", "AUDIT_OPEN"}
_EXIT = {"ANTI_SANDBOX_EXIT"}


def escalate(telemetry: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Any blocked process spawn, network attempt or credential recon = MALICIOUS.
    A model checkpoint has no reason to do any of these while loading."""
    buckets = {"PROCESS_EXEC": [], "NETWORK_EGRESS": [], "CREDENTIAL_RECON": [], "ANTI_SANDBOX_EXIT": []}
    for ev in telemetry or []:
        name = ev.get("event")
        if name in _PROCESS:
            buckets["PROCESS_EXEC"].append(ev)
        elif name in _NETWORK:
            buckets["NETWORK_EGRESS"].append(ev)
        elif name in _RECON:
            buckets["CREDENTIAL_RECON"].append(ev)
        elif name in _EXIT:
            buckets["ANTI_SANDBOX_EXIT"].append(ev)
    for vector in ("PROCESS_EXEC", "NETWORK_EGRESS", "CREDENTIAL_RECON", "ANTI_SANDBOX_EXIT"):
        if buckets[vector]:
            return _result("MALICIOUS", vector,
                           f"honeypot recorded {len(buckets[vector])} "
                           f"{vector.lower().replace('_', ' ')} event(s)",
                           evidence=buckets[vector][:10])
    return _result("BENIGN", "NONE", "no process, network or recon events", evidence=[])


def apply_policy(report: Dict[str, Any], static: Dict[str, Any] | None,
                 esc: Dict[str, Any]) -> Dict[str, Any]:
    """Final verdict = worst of sandbox report, static pass and honeypot."""
    # run_sandbox() reports ANY load/fuzz exception as MALICIOUS/CORRUPT_OR_EXPLOIT.
    # A broken or password-protected file fails to load too, so on its own that is
    # only suspicious. Real attacks are still caught by the static pass and by the
    # honeypot events (blocked process/network/recon) below.
    if report.get("attack_vector") == "CORRUPT_OR_EXPLOIT":
        report["verdict"] = "SUSPICIOUS"
        report["confidence"] = "LOW"
        report["attack_vector"] = "LOAD_FAILURE"
        report["summary"] = "could not load or fuzz the file (not proof of malice): " + str(report.get("summary", ""))

    candidates = [("sandbox", report)]
    if static is not None:
        candidates.append(("static", static))
    candidates.append(("honeypot", esc))

    source, winner = max(candidates, key=lambda c: RANK.get(str(c[1].get("verdict")).upper(), 1))
    # max() keeps the first of equal candidates, so ties favour the sandbox report.
    details = report.setdefault("technical_details", {})
    details["static"] = static
    details["escalation"] = esc
    details["decided_by"] = source
    if source != "sandbox":
        report["verdict"] = winner["verdict"]
        report["attack_vector"] = winner["attack_vector"]
        report["summary"] = winner["summary"]
        report["confidence"] = "HIGH" if winner["verdict"] == "MALICIOUS" else "MEDIUM"
    return report
