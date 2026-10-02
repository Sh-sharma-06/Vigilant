import os
import sys
import subprocess
import time
import json
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / "eval_dataset"
LOGS_DIR = BASE_DIR / "logs"
SANDBOX_RUNNER = BASE_DIR / "sandbox_runner.py"
TRIAGE_AGENT = BASE_DIR / "triage_agent.py"

VALID_EXTENSIONS = (".pkl", ".pt", ".bin")

def main():
    if not DATASET_DIR.exists():
        print(f"[!] Dataset directory not found at: {DATASET_DIR}")
        sys.exit(1)

    LOGS_DIR.mkdir(exist_ok=True)
    temp_terminal_file = LOGS_DIR / "temp_terminal.txt"

    model_files = sorted([f for f in DATASET_DIR.iterdir() if f.suffix.lower() in VALID_EXTENSIONS])

    print("=" * 60)
    print(f"=== Vigilant End-to-End Pipeline: Scanning {len(model_files)} Models ===")
    print("=" * 60 + "\n")

    results = {"BENIGN": [], "MALICIOUS": [], "UNKNOWN": []}

    for idx, model_path in enumerate(model_files, start=1):
        print(f"[{idx}/{len(model_files)}] Detonating: {model_path.name}")
        
        # 1. Run the Sandbox
        cmd_sandbox = [sys.executable, str(SANDBOX_RUNNER), str(model_path)]
        process = subprocess.run(
            cmd_sandbox,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False
        )
        
        # 2. Save the raw terminal output
        with open(temp_terminal_file, "w") as f:
            f.write(process.stdout.strip())
            
        # 3. Trigger Gemma Triage Agent (No capture_output, so it streams live to the screen!)
        cmd_triage = [sys.executable, str(TRIAGE_AGENT), model_path.name, str(temp_terminal_file)]
        subprocess.run(cmd_triage)
        
        print("-" * 60 + "\n")

        # 4. Read the generated JSON report to tally the verdict
        report_path = LOGS_DIR / f"{model_path.name}_report.json"
        if report_path.exists():
            try:
                with open(report_path, "r") as f:
                    report_data = f.read()
                    
                    # BUG FIXED: Checking uppercase against uppercase!
                    data_upper = report_data.upper()
                    if '"VERDICT": "MALICIOUS"' in data_upper or "**VERDICT:** MALICIOUS" in data_upper:
                        results["MALICIOUS"].append(model_path.name)
                    else:
                        results["BENIGN"].append(model_path.name)
            except Exception:
                results["UNKNOWN"].append(model_path.name)
        else:
            results["UNKNOWN"].append(model_path.name)

        # Give the OS a half-second to reclaim RAM before spinning up the next Docker container
        time.sleep(0.5)

    # ==========================================
    # 5. PRINT FINAL SUMMARY
    # ==========================================
    print("=" * 60)
    print("=== Final Pipeline Evaluation Summary ===")
    print("=" * 60)
    print(f"Total Scanned : {len(model_files)}")
    print(f"Clean (Benign): {len(results['BENIGN'])}")
    print(f"Flagged/Blocked: {len(results['MALICIOUS'])}")
    if results["UNKNOWN"]:
        print(f"Failed to Parse: {len(results['UNKNOWN'])}")

    if results["MALICIOUS"]:
        print("\nFlagged Models:")
        for name in results["MALICIOUS"]:
            print(f"  - {name}")

if __name__ == "__main__":
    main()
