"""
baseline_categories.py

Skeleton for the Day 2 work: replace analyzer.py's flat "any external IP
is suspicious" rule (see the TODO at analyzer.py line 34 -- "Implement
Phase 4 Category-Based Domain Allowlist") with a per-category deviation
check.

Matches analyze_telemetry()'s actual parsed_data schema, as produced by
telemetry_parser.parse_strace():
  {
    "processes": [{"binary": str, "command": str}, ...],
    "files_written": [str, ...],
    "network_connections": [{"destination_ip": str, "port": int}, ...],
  }

Not wired into analyzer.py yet -- CATEGORY_PROFILES is empty until the
Day 2 data-collection pass (3-5 benign HF models per category, run
through sandbox_runner.detonate_model + telemetry_parser.parse_strace)
happens on the server.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CategoryProfile:
    name: str
    expected_hosts: set[str] = field(default_factory=set)
    expected_file_prefixes: set[str] = field(default_factory=set)
    expected_child_processes: set[str] = field(default_factory=set)  # basenames, e.g. "python3"
    sample_count: int = 0


CATEGORY_PROFILES: dict[str, CategoryProfile] = {
    "vision_audio_inference": CategoryProfile(name="vision_audio_inference"),
    "llm_tokenizer": CategoryProfile(name="llm_tokenizer"),
    "embedding": CategoryProfile(name="embedding"),
    "custom_c_extension": CategoryProfile(name="custom_c_extension"),
}


def classify_model(model_name: str, model_metadata: dict) -> str:
    """Stub -- replace with real logic once categories are settled (e.g.
    config.json architecture field, or a manual mapping for the initial
    3-5-per-category benign set)."""
    raise NotImplementedError("Wire up real classification once Day 2 data is collected")


def score_against_baseline(category: str, parsed_telemetry: dict) -> dict:
    """
    Drop-in replacement for analyzer.py's flat network-connection rule
    (lines 31-38). Same parsed_telemetry shape analyze_telemetry() already
    receives.
    """
    profile = CATEGORY_PROFILES.get(category)
    if profile is None or profile.sample_count == 0:
        return {
            "status": "NO_BASELINE",
            "note": f"No collected baseline for '{category}' yet -- "
                    "analyzer.py should fall back to the flat external-IP rule until this lands.",
        }

    deviations = []
    for conn in parsed_telemetry.get("network_connections", []):
        ip = conn.get("destination_ip")
        if ip not in profile.expected_hosts and ip not in ("127.0.0.1", "0.0.0.0"):
            deviations.append(f"unexpected connection to {ip}:{conn.get('port')}")

    for path in parsed_telemetry.get("files_written", []):
        if not any(path.startswith(prefix) for prefix in profile.expected_file_prefixes):
            deviations.append(f"unexpected file write: {path}")

    for proc in parsed_telemetry.get("processes", []):
        import os
        basename = os.path.basename(proc.get("binary", "")).lower()
        if basename not in profile.expected_child_processes:
            deviations.append(f"unexpected child process: {basename}")

    return {
        "status": "DEVIATION" if deviations else "WITHIN_BASELINE",
        "deviations": deviations,
        "category": category,
        "baseline_sample_count": profile.sample_count,
    }
