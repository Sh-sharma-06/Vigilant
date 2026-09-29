import os
import subprocess
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
LOG_DIR = PROJECT_DIR / "logs"
SANDBOX_IMAGE = "vigilant-sandbox"


def run_sandbox(model_path: str) -> str:
    """Detonate one model with no host writes outside the dedicated log folder."""
    LOG_DIR.mkdir(exist_ok=True)
    for log_file in (LOG_DIR / "strace_output.log", LOG_DIR / "report.json"):
        if log_file.exists():
            log_file.unlink()

    host_model = Path(model_path).resolve()
    if not host_model.is_file():
        print(f"Model file not found: {host_model}")
        return "ERROR_INVALID_PATH"

    model_dir = host_model.parent
    container_model = f"/sandbox/model/{host_model.name}"
    docker_cmd = [
        "docker", "run", "--rm", "--network", "fakenet-isolated",
        "--user", "10001:10001", "--security-opt", "no-new-privileges=true",
        "--cap-drop", "ALL", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--memory=2g", "--cpus=1.0", "--pids-limit=50",
        "-v", f"{model_dir}:/sandbox/model:ro", "-v", f"{LOG_DIR}:/sandbox/logs",
        SANDBOX_IMAGE, "strace", "-f", "-s", "4096", "-o", "/sandbox/logs/strace_output.log",
        "python", "/sandbox/run_model.py", container_model,
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
