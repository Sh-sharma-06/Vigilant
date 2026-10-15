"""
Vigilant Unified Format Dispatcher
==================================
Magic-byte sniffer + master router. Never trusts file extensions.

Routing
-------
  Pickle / PyTorch-ZIP  -> hardened sandbox_runner (honeypot armed)
  SAFETENSORS           -> inspectors.safetensors_scanner
  ONNX                  -> inspectors.onnx_scanner
  HDF5                  -> inspectors.hdf5_scanner
  GGUF                  -> inspectors.gguf_scanner
  Unknown               -> SUSPICIOUS / LOW-confidence report
"""
from __future__ import annotations

import json
import os
import pickletools
import behavior_sim
from typing import Any, Dict, Optional

from inspectors.safetensors_scanner import scan_safetensors
from inspectors.onnx_scanner import scan_onnx
from inspectors.hdf5_scanner import scan_hdf5
from inspectors.gguf_scanner import scan_gguf
from verdict_policy import apply_policy, escalate, static_verdict

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
GGUF_MAGIC = b"GGUF"
ZIP_MAGIC = b"PK\x03\x04"
PICKLE_MAGIC_RANGE = range(0x80, 0x86)   # protocols 0-5 lead with \x80N


def _parses_as_pickle(path: str, limit: int = 64 * 1024 * 1024) -> bool:
    """Protocol 0/1 pickles have no \\x80 header byte. Accept a file whose opcodes
    parse cleanly up to STOP. This only READS opcodes; nothing is executed."""
    try:
        if os.path.getsize(path) > limit:
            return False
        with open(path, "rb") as fh:
            for _ in pickletools.genops(fh):
                pass
        return True
    except Exception:
        return False


def sniff_format(path: str) -> str:
    """Identify the container from the first 16 bytes (extension ignored)."""
    with open(path, "rb") as fh:
        head = fh.read(16)

    if not head:
        return "UNKNOWN"
    if head.startswith(HDF5_MAGIC):
        return "HDF5"
    if head.startswith(GGUF_MAGIC):
        return "GGUF"
    if head.startswith(ZIP_MAGIC):
        return "PYTORCH_ZIP"          # PyTorch checkpoints are ZIP archives
    if head[0] in PICKLE_MAGIC_RANGE:
        return "PICKLE"

    # Safetensors: 8-byte LE header length followed by '{' JSON
    import struct
    if len(head) >= 9:
        (hlen,) = struct.unpack("<Q", head[:8])
        if 0 < hlen <= 100 * 1024 * 1024 and head[8:9] == b"{":
            return "SAFETENSORS"

    # ONNX: protobuf with field 1 (ir_version, varint) = 0x08 tag up front
    if head[0] == 0x08:
        return "ONNX"
    if _parses_as_pickle(path):       # old-style (protocol 0/1) pickle
        return "PICKLE"
    return "UNKNOWN"


def _unknown_report(path: str) -> Dict[str, Any]:
    return {
        "model_name": os.path.basename(path),
        "format": "UNKNOWN",
        "verdict": "SUSPICIOUS",
        "confidence": "LOW",
        "attack_vector": "NONE",
        "summary": "Unrecognized magic bytes; no inspector available.",
        "technical_details": {},
    }


def dispatch(path: str,
             sandbox_runner: Optional[Any] = None,
             arm_honeypot: bool = True,
             static_first: bool = True) -> Dict[str, Any]:
    """
    Route *path* to the right subsystem and return Vigilant telemetry.

    For PICKLE / PYTORCH_ZIP, `sandbox_runner` (a callable taking the path,
    or an object exposing `.run(path)`) is invoked with the honeypot engine
    armed; without a runner a guarded stub report is returned.
    """
    fmt = sniff_format(path)
    name = os.path.basename(path)

    if fmt in ("PICKLE", "PYTORCH_ZIP"):
        honeypot_summary: Dict[str, Any] = {}
        runner_report: Optional[Dict[str, Any]] = None
        telemetry: list = []

        # Step 1: static pass. It never executes the file. If it already finds
        # a dangerous callable we stop here and do NOT detonate the file.
        static = static_verdict(path) if static_first else None
        if static is not None and static["verdict"] == "MALICIOUS":
            return {
                "model_name": name, "format": fmt, "verdict": "MALICIOUS",
                "confidence": "HIGH", "attack_vector": static["attack_vector"],
                "summary": static["summary"] + " (file not executed)",
                "technical_details": {"static": static, "decided_by": "static"},
            }
        if arm_honeypot:
            from interceptors.honeypot_engine import (
                HoneypotEngine, HoneytokenExfiltrationAlert)
            engine = HoneypotEngine()
            engine.start()
            try:
                runner_report = behavior_sim.run_sessions(lambda: _run_sandbox(sandbox_runner, path))
            except HoneytokenExfiltrationAlert as alert:
                return {
                    "model_name": name, "format": fmt, "verdict": "MALICIOUS",
                    "confidence": "HIGH", "attack_vector": "HONEYTOKEN_EXFIL",
                    "summary": f"Honeytoken exfiltration caught: "
                               f"{alert.token.token_type} -> {alert.endpoint}",
                    "technical_details": {"honeypot": engine.summary()},
                }
            finally:
                if engine.active:
                    engine.stop()
                honeypot_summary = engine.summary()
                telemetry = list(engine.telemetry) + behavior_sim.drain_events()
        else:
            runner_report = behavior_sim.run_sessions(lambda: _run_sandbox(sandbox_runner, path))
            telemetry = behavior_sim.drain_events()

        base = runner_report or {
            "verdict": "SUSPICIOUS", "confidence": "LOW",
            "attack_vector": "NONE",
            "summary": "Pickle-family container staged for sandboxed "
                       "dynamic analysis (no runner attached).",
        }
        details = base.pop("technical_details", {}) or {}
        details["honeypot"] = honeypot_summary
        report = {"model_name": name, "format": fmt, "technical_details": details,
                  **base}
        # Step 3: final verdict = worst of sandbox, static and honeypot events.
        return apply_policy(report, static, escalate(telemetry))

    if fmt == "SAFETENSORS":
        return scan_safetensors(path)
    if fmt == "ONNX":
        return scan_onnx(path)
    if fmt == "HDF5":
        return scan_hdf5(path)
    if fmt == "GGUF":
        return scan_gguf(path)

    # Unknown container. It may still be a truncated or damaged pickle whose
    # payload sits before the bad bytes, so let the static pass have a look.
    if static_first:
        static = static_verdict(path)
        if static["verdict"] == "MALICIOUS":
            return {
                "model_name": name, "format": fmt, "verdict": "MALICIOUS",
                "confidence": "HIGH", "attack_vector": static["attack_vector"],
                "summary": static["summary"] + " (unrecognised container, file not executed)",
                "technical_details": {"static": static, "decided_by": "static"},
            }
    return _unknown_report(path)


def _run_sandbox(runner: Optional[Any], path: str) -> Optional[Dict[str, Any]]:
    if runner is None:
        return None
    if callable(runner):
        return runner(path)
    if hasattr(runner, "run"):
        return runner.run(path)
    raise TypeError("sandbox_runner must be callable or expose .run(path)")


if __name__ == "__main__":
    import sys
    for target in sys.argv[1:]:
        print(json.dumps(dispatch(target), indent=2, default=str))
