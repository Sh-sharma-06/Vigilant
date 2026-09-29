"""
Automated check that the dynamic sandbox correctly distinguishes a delayed,
usage-conditioned trigger (canary_model.pt) from ordinary benign behavior
(benign_model.pt).

Run with: python test_pipeline.py
"""
import subprocess
import os
import sys

EXPECTED_MARKERS = ["canary_fired.txt", "93.184.216.34"]


def run_and_capture(model_file):
    """Run sandbox_runner.py and return the resulting strace log contents."""
    subprocess.run(["python", "sandbox_runner.py", model_file], check=True)
    with open("logs/strace_output.log") as f:
        return f.read()


def check_markers_present(log_text, model_name):
    found = [m for m in EXPECTED_MARKERS if m in log_text]
    return found


def main():
    print("=== Testing canary_model.pt (expect BOTH markers present) ===")
    canary_log = run_and_capture("canary_model.pt")
    canary_found = check_markers_present(canary_log, "canary")
    canary_ok = len(canary_found) == len(EXPECTED_MARKERS)
    print(f"Markers found: {canary_found} -> {'PASS' if canary_ok else 'FAIL'}")

    print("\n=== Testing benign_model.pt (expect NO markers present) ===")
    benign_log = run_and_capture("benign_model.pt")
    benign_found = check_markers_present(benign_log, "benign")
    benign_ok = len(benign_found) == 0
    print(f"Markers found: {benign_found} -> {'PASS' if benign_ok else 'FAIL'}")

    print("\n=== Summary ===")
    if canary_ok and benign_ok:
        print("PASS: sandbox correctly distinguishes delayed-trigger from benign behavior.")
        sys.exit(0)
    else:
        print("FAIL: sandbox did not behave as expected. See details above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
