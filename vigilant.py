#!/usr/bin/env python3
"""
vigilant.py - scan any model file (or a whole folder) BEFORE you load it.

  python3 vigilant.py scan model.pt
  python3 vigilant.py scan ./downloads --json
  python3 vigilant.py scan model.pt --dry-run     (print the Docker command, run nothing)

How it decides
  1. The file is read as BYTES only (never loaded on this machine): format sniffing,
     then the static pass. A dangerous callable means MALICIOUS and the file is never run.
  2. Pickle-family files that look clean are detonated INSIDE Docker (no network,
     all capabilities dropped, memory/CPU/process limits, repo and model mounted read-only).
  3. Anything that stops the sandbox from giving an answer (timeout, killed, crashed)
     is never reported as clean.

Exit code: 0 clean, 1 suspicious, 2 malicious, 3 could not scan (Docker or file problem).
Settings live in vigilant_config.json (optional); see DEFAULTS below for every key.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

import model_dispatcher
from verdict_policy import POLICY_VERSION, static_verdict

HERE = os.path.dirname(os.path.abspath(__file__))
RANK = {"BENIGN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

DEFAULTS: Dict[str, Any] = {
    "image": "python:3.12-slim",       # Docker image used for the sandbox
    "memory": "2g",                    # RAM limit for the sandbox
    "cpus": "2",                       # CPU limit for the sandbox
    "pids_limit": 256,                 # max processes inside the sandbox
    "timeout_seconds": 120,            # wall-clock limit per file
    "sessions": 7,                     # simulated dates to try (1-7, see behavior_sim.py)
    "cache_dir": "vigilant_scan_cache",  # verdict cache, keyed by file content
    "terminated_is_malicious": False,  # True: a sandbox that dies without an answer counts as MALICIOUS
}

INNER_COMMAND = ("mkdir -p /work && cp -r /src/. /work/ && cd /work && "
                 "rm -rf vigilant_cache && python vigilant_one.py /model/input --no-cache")
INFRA_MARKERS = ("Cannot connect to the Docker daemon", "permission denied while trying to connect",
                 "Unable to find image", "pull access denied", "Is the docker daemon running",
                 "error during connect")


class ScanInfrastructureError(Exception):
    """Docker or the file itself could not be used. Never turned into a verdict."""


# ------------------------------------------------------------------ config ----
def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    cfg = dict(DEFAULTS)
    if path is None:
        for candidate in (os.path.join(os.getcwd(), "vigilant_config.json"),
                          os.path.join(HERE, "vigilant_config.json")):
            if os.path.exists(candidate):
                path = candidate
                break
    if path:
        with open(path) as fh:
            user = json.load(fh)
        unknown = sorted(set(user) - set(DEFAULTS))
        if unknown:
            raise ValueError(f"unknown setting(s) in {path}: {unknown}")
        cfg.update(user)
    cfg["sessions"] = max(1, min(int(cfg["sessions"]), 7))
    return cfg


def _fingerprint(cfg: Dict[str, Any]) -> str:
    keys = ("image", "memory", "cpus", "pids_limit", "sessions", "terminated_is_malicious")
    blob = json.dumps({k: cfg[k] for k in keys}, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:8]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ docker ----
def docker_command(path: str, cfg: Dict[str, Any], name: str) -> List[str]:
    return [
        "docker", "run", "--rm", "--name", name,
        "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", str(cfg["pids_limit"]), "--memory", str(cfg["memory"]), "--cpus", str(cfg["cpus"]),
        "-e", f"VIGILANT_SESSIONS={cfg['sessions']}",
        "-v", f"{HERE}:/src:ro",
        "-v", f"{os.path.abspath(path)}:/model/input:ro",
        cfg["image"], "bash", "-c", INNER_COMMAND,
    ]


def parse_container_output(returncode: int, stdout: str, stderr: str) -> Dict[str, Any]:
    """Turn what Docker printed into an outcome. The model controls stdout, so only
    the LAST result line of a run that ended cleanly (exit 0) is trusted."""
    err = (stderr or "").strip()
    if returncode in (125, 126, 127) or any(m in err for m in INFRA_MARKERS):
        return {"kind": "infra", "detail": err[-300:] or f"docker exited with {returncode}"}
    lines = [ln for ln in (stdout or "").splitlines() if ln.startswith("VIGILANT_RESULT:")]
    if returncode == 0 and lines:
        try:
            return {"kind": "result", "report": json.loads(lines[-1].split(":", 1)[1])}
        except ValueError:
            pass
    return {"kind": "terminated", "code": returncode, "detail": err[-300:]}


def run_in_docker(path: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    name = "vigilant-" + uuid.uuid4().hex[:12]
    try:
        proc = subprocess.run(docker_command(path, cfg, name), capture_output=True, text=True,
                              timeout=int(cfg["timeout_seconds"]))
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return {"kind": "timeout"}
    except FileNotFoundError:
        return {"kind": "infra", "detail": "docker is not installed or not on PATH"}
    return parse_container_output(proc.returncode, proc.stdout, proc.stderr)


# -------------------------------------------------------------------- scan ----
def _report(name: str, fmt: str, verdict: str, confidence: str, vector: str, summary: str,
            **details: Any) -> Dict[str, Any]:
    return {"model_name": name, "format": fmt, "verdict": verdict, "confidence": confidence,
            "attack_vector": vector, "summary": summary, "technical_details": details}


def _from_outcome(name: str, fmt: str, outcome: Dict[str, Any], cfg: Dict[str, Any],
                  static: Dict[str, Any]) -> Dict[str, Any]:
    kind = outcome["kind"]
    if kind == "infra":
        raise ScanInfrastructureError(outcome.get("detail", "docker problem"))
    if kind == "result":
        rep = outcome["report"]
        rep.setdefault("technical_details", {})["host_static"] = static
        rep["model_name"] = name
        return rep
    if kind == "timeout":
        return _report(name, fmt, "SUSPICIOUS", "LOW", "SANDBOX_TIMEOUT",
                       f"the sandbox did not finish within {cfg['timeout_seconds']}s", host_static=static)
    verdict = "MALICIOUS" if cfg["terminated_is_malicious"] else "SUSPICIOUS"
    return _report(name, fmt, verdict, "LOW", "SANDBOX_TERMINATED",
                   "the sandbox ended without giving an answer (killed, crashed or out of memory): "
                   f"exit {outcome.get('code')} {outcome.get('detail', '')}".strip(), host_static=static)


def scan_file(path: str, cfg: Dict[str, Any], runner: Optional[Callable] = None,
              use_cache: bool = True) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise ScanInfrastructureError(f"not a file: {path}")
    if not os.stat(path).st_mode & 0o004:
        raise ScanInfrastructureError(f"{path} is not world-readable, so the sandbox (no capabilities) could not "
                                      "open it. Run: chmod a+r <file>")
    started = time.time()
    name = os.path.basename(path)
    sha = _sha256(path)
    cache_file = os.path.join(HERE, cfg["cache_dir"], f"{sha}.v{POLICY_VERSION}.{_fingerprint(cfg)}.json")
    if use_cache and os.path.exists(cache_file):
        with open(cache_file) as fh:
            cached = json.load(fh)
        cached.update({"model_name": name, "cached": True})
        return cached

    fmt = model_dispatcher.sniff_format(path)
    cacheable = use_cache                   # --no-cache: neither read nor write the cache
    if fmt in ("PICKLE", "PYTORCH_ZIP"):
        static = static_verdict(path)
        if static["verdict"] == "MALICIOUS":
            result = _report(name, fmt, "MALICIOUS", "HIGH", static["attack_vector"],
                             static["summary"] + " (file not executed)", static=static, decided_by="static")
        else:
            outcome = (runner or run_in_docker)(path, cfg)
            result = _from_outcome(name, fmt, outcome, cfg, static)
            cacheable = use_cache and outcome["kind"] == "result"
    else:                                   # inspectors / unknown containers read bytes only
        result = model_dispatcher.dispatch(path)
    result.update({"sha256": sha, "format": fmt, "model_name": name, "cached": False,
                   "scan_seconds": round(time.time() - started, 2)})
    if cacheable:
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        with open(cache_file, "w") as fh:
            json.dump(result, fh, default=str)
    return result


def _collect(path: str) -> List[str]:
    if os.path.isdir(path):
        found = []
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            found += [os.path.join(root, f) for f in sorted(files) if not f.startswith(".")]
        return found
    return [path]


def main(argv: Optional[List[str]] = None, runner: Optional[Callable] = None) -> int:
    ap = argparse.ArgumentParser(prog="vigilant", description="Scan model files before you load them.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan a file or a folder")
    sc.add_argument("path")
    sc.add_argument("--config", help="path to a settings file (default: vigilant_config.json if present)")
    sc.add_argument("--json", action="store_true", help="print the full report as JSON")
    sc.add_argument("--no-cache", action="store_true", help="ignore and do not write the verdict cache")
    sc.add_argument("--dry-run", action="store_true", help="print the Docker command and exit")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    files = _collect(args.path)
    if args.dry_run:
        print(shlex.join(docker_command(files[0], cfg, "vigilant-DRYRUN")))
        return 0

    results: List[Dict[str, Any]] = []
    infra_problem = False
    for f in files:
        try:
            results.append(scan_file(f, cfg, runner=runner, use_cache=not args.no_cache))
        except ScanInfrastructureError as exc:
            results.append({"model_name": os.path.basename(f), "verdict": "ERROR", "summary": str(exc)})
            infra_problem = True
            break                           # Docker is down or the path is bad: no point continuing
    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        for r in results:
            print(f"{r['verdict']:<10} {r['model_name']}  [{r.get('attack_vector', '-')}]  {r.get('summary', '')}")
        if infra_problem:
            print(f"\nscan stopped after {len(results) - 1} file(s)")
        else:
            worst = max((RANK.get(r["verdict"], 0) for r in results), default=0)
            print(f"\n{len(results)} file(s) scanned; worst verdict: {[k for k, v in RANK.items() if v == worst][0]}")
    if infra_problem:
        print("COULD NOT SCAN: " + results[-1]["summary"], file=sys.stderr)
        return 3
    return max((RANK.get(r["verdict"], 0) for r in results), default=0)


if __name__ == "__main__":
    sys.exit(main())
