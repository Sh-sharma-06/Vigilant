"""
test_matrix.py

Re-runs the 4-quadrant test matrix (static/dynamic x benign/malicious)
against the FIXED pickle_scanner.py (nn.Module allowlist + __builtin__
alias normalization) and the existing sandbox pipeline.

Matches your actual module interfaces:
  pickle_scanner.scan_file(Path) -> dict            (file/verdict/streams)
  sandbox_runner.detonate_model(filename) -> None   (writes ./strace_output.log)
  telemetry_parser.parse_strace(log_path) -> dict   (processes/files_written/network_connections)
  analyzer.analyze_telemetry(parsed) -> dict         (verdict/risk_score/flags)

Run from the repo root (same directory as the model .pt files), because
sandbox_runner mounts cwd into the container.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from pickle_scanner import scan_file
from sandbox_runner import detonate_model
from telemetry_parser import parse_strace
from analyzer import analyze_telemetry

MODELS = {
    "benign": "benign_model.pt",
    "malicious": "canary_model.pt",  # stand-in for delayed_malware.pt
}

STRACE_LOG = Path("strace_output.log")


def run_static(filename: str) -> dict:
    result = scan_file(Path(filename))
    return {"verdict": result["verdict"]}


def run_dynamic(filename: str, archive_log_as: str) -> dict:
    detonate_model(filename)  # writes ./strace_output.log, prints to stdout

    if not STRACE_LOG.exists():
        return {"verdict": "ERROR", "reason": "strace_output.log not produced"}

    parsed = parse_strace(str(STRACE_LOG))
    result = analyze_telemetry(parsed)

    # Preserve this run's log before the next model's run overwrites it.
    shutil.copy(STRACE_LOG, archive_log_as)

    return {"verdict": result["verdict"], "risk_score": result["risk_score"], "flags": result["flags"]}


def main() -> None:
    results: dict[str, dict] = {}

    for label, filename in MODELS.items():
        if not Path(filename).exists():
            print(f"[!] {filename} not found in cwd -- skipping {label}")
            continue

        print(f"=== {label}: {filename} ===")
        static = run_static(filename)
        print(f"  static:  {static['verdict']}")

        dynamic = run_dynamic(filename, archive_log_as=f"strace_output_{label}.log")
        print(f"  dynamic: {dynamic['verdict']}"
              f"{' (score ' + str(dynamic['risk_score']) + ')' if 'risk_score' in dynamic else ''}")

        results[label] = {"static": static, "dynamic": dynamic}

    Path("test_matrix_results.json").write_text(json.dumps(results, indent=2))
    print("\nWrote test_matrix_results.json")

    # Sanity checks against the expected post-fix outcome
    if "benign" in results and results["benign"]["static"]["verdict"] != "clean":
        print("[!] benign_model.pt is STILL flagged suspicious by the static scanner -- "
              "check the allowlist / __builtin__ alias fix.")
    if "malicious" in results and results["malicious"]["static"]["verdict"] != "suspicious":
        print("[!] canary_model.pt was NOT flagged by the static scanner -- "
              "expected, since CanaryModel is a custom class outside the allowlist.")


if __name__ == "__main__":
    main()
