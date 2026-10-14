import subprocess, json, os, sys, re

def detonate_in_container(model_path):
    abs_path = os.path.abspath(model_path)
    filename = os.path.basename(model_path)

    cmd = [
        "docker", "run", "--rm",
        "--add-host=host.docker.internal:host-gateway", # Connect Gemma
        "--network=bridge",          # Enable internal bridge for Gemma
        "--memory=4g",               # Massive memory boost to prevent PyTorch crashes
        "--cpus=2.0",
        "-v", f"{abs_path}:/target/{filename}:ro",
        "vigilant-sandbox",
        f"/target/{filename}"
    ]

    try:
        # Increased timeout to 15s to give Gemma time to think
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15.0)
        output = result.stdout.strip()
        match = re.search(r'(\{[\s\S]*\})', output)
        if match: return json.loads(match.group(1))

        return {"model_name": filename, "format": "UNKNOWN", "verdict": "SUSPICIOUS", "confidence": "LOW", "attack_vector": "CONTAINER_ERROR", "summary": f"Container failed. stderr: {result.stderr.strip()}", "technical_details": {}}
    except subprocess.TimeoutExpired:
        return {"model_name": filename, "format": "UNKNOWN", "verdict": "MALICIOUS", "confidence": "HIGH", "attack_vector": "TIMEOUT_EVASION", "summary": "Execution timed out (evasion sleep attempt).", "technical_details": {}}
    except Exception as e:
        return {"model_name": filename, "format": "UNKNOWN", "verdict": "SUSPICIOUS", "confidence": "LOW", "attack_vector": "ORCHESTRATION_ERROR", "summary": f"Host error: {str(e)}", "technical_details": {}}

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    print(json.dumps(detonate_in_container(sys.argv[1]), indent=2))
