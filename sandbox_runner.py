import subprocess
import os
import sys

def detonate_model(model_filename):
    print(f"[*] Provisioning isolated container for {model_filename}...")
    
    # Get the absolute path to mount the current directory into the container
    current_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Docker command to run the micro-sandbox
    # --rm deletes the container immediately after execution
    # -v mounts the directory so strace can save the log file back to the host
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{current_dir}:/app",
        "ml-sandbox",
        "strace", "-f", "-e", "trace=file,process,network", "-o", "/app/strace_output.log",
        "python", "run_model.py", model_filename
    ]
    
    try:
        print("[*] Detonating payload and capturing syscalls...")
        subprocess.run(cmd, capture_output=True, text=True)
        print("[*] Execution finished. Container destroyed.")
        print("[*] Telemetry saved to strace_output.log")
    except Exception as e:
        print(f"[!] Sandbox error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        detonate_model(sys.argv[1])
    else:
        print("Usage: python sandbox_runner.py <model_file.pkl>")
