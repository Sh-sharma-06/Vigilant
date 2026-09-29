import os
import shlex
import subprocess
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
LOG_DIR = PROJECT_DIR / "logs"
SANDBOX_IMAGE = "vigilant-sandbox"


def run_sandbox(model_path: str) -> str:
    """Detonate a project-local model and return a non-success status on failure."""
    LOG_DIR.mkdir(exist_ok=True)
    for log_file in (LOG_DIR / "strace_output.log", LOG_DIR / "report.json"):
        if log_file.exists():
            log_file.unlink()

    try:
        relative_model = Path(model_path).resolve().relative_to(PROJECT_DIR)
    except ValueError:
        print("Model path must be inside the Vigilant project directory.")
        return "ERROR_INVALID_PATH"

    host_model = PROJECT_DIR / relative_model
    if not host_model.is_file():
        print(f"Model file not found: {host_model}")
        return "ERROR_INVALID_PATH"

    safe_model = shlex.quote(f"/sandbox/{relative_model.as_posix()}")
    docker_cmd = [
        "docker", "run", "--rm", "--network", "fakenet-isolated",
        "--cap-drop", "ALL", "--read-only", "--memory=2g", "--cpus=1.0", "--pids-limit=50",
        "-v", f"{PROJECT_DIR}:/sandbox:ro", "-v", f"{LOG_DIR}:/tmp/logs",
        SANDBOX_IMAGE, "bash", "-c",
        "strace -f -s 4096 -o /tmp/logs/strace_output.log "
        f"python /sandbox/run_model.py {safe_model}",
    ]
    try:
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("Sandbox execution timed out.")
        return "ERROR_TIMEOUT"
    except OSError as error:
        print(f"Sandbox could not be started: {error}")
        return "ERROR"

    if result.stdout:
        print(result.stdout, end="")
    if result.returncode != 0:
        print(f"Sandbox failed/crashed. Error: {result.stderr}")
        return "ERROR"
    if not (LOG_DIR / "strace_output.log").is_file():
        print("Sandbox completed without producing telemetry.")
        return "ERROR"
    print(f"Telemetry saved to {LOG_DIR / 'strace_output.log'}")
    return "SUCCESS"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sandbox_runner.py <model_file>")
        sys.exit(2)
    sys.exit(0 if run_sandbox(sys.argv[1]) == "SUCCESS" else 1)
