#!/usr/bin/env python3
"""Single fail-closed entry point for the Vigilant model-analysis workflow."""

import json
import sys
from pathlib import Path

from analyzer import analyze_telemetry
from pickle_scanner import scan_file
from sandbox_runner import LOG_DIR, run_sandbox
from telemetry_parser import parse_strace


FINAL_REPORT = Path(__file__).resolve().parent / "final_report.json"


def _write_report(report: dict) -> None:
    FINAL_REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")


def run_pipeline(model_path: str) -> int:
    model = Path(model_path).resolve()
    report: dict = {"model": str(model)}
    if not model.is_file():
        report.update({"verdict": "ERROR", "error": "model file not found"})
        _write_report(report)
        return 1

    from typosquat_registry import TyposquatRegistry

    registry = TyposquatRegistry()
    # Registry keys are canonical model names without serialization suffixes.
    registry_result = registry.check_model(model.stem, model)
    report["registry"] = registry_result
    if registry_result["status"] != "safe":
        report.update({"verdict": "REJECTED", "error": "registry hash verification failed"})
        _write_report(report)
        return 1

    static_result = scan_file(model)
    report["static"] = static_result
    if static_result["verdict"] in {"error", "unparseable"}:
        report.update({"verdict": "ERROR", "error": "static scan could not complete"})
        _write_report(report)
        return 1

    sandbox_status = run_sandbox(str(model))
    report["sandbox"] = {"status": sandbox_status}
    if sandbox_status != "SUCCESS":
        report.update({"verdict": "ERROR", "error": "dynamic sandbox did not complete"})
        _write_report(report)
        return 1

    telemetry = parse_strace(LOG_DIR / "strace_output.log")
    report["telemetry"] = telemetry
    report["behavioral"] = analyze_telemetry(telemetry)

    try:
        # Optional at import time so static validation remains usable if the
        # local LLM client dependencies are not installed yet.
        from triage_agent import TriageAgent

        triage_report = TriageAgent().triage(static_result, telemetry).model_dump()
    except Exception as error:
        # A missing/unavailable LLM must not be interpreted as a safe model.
        triage_report = {
            "verdict": "uncertain-needs-review",
            "confidence": 0.0,
            "findings": [],
            "summary": f"LLM triage unavailable: {error}",
        }
    report["triage"] = triage_report
    report["verdict"] = report["behavioral"]["verdict"]
    _write_report(report)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vigilant_pipeline.py <path_to_model>")
        sys.exit(2)
    sys.exit(run_pipeline(sys.argv[1]))
