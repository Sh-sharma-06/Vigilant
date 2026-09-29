import sys
import json
import os

def analyze_telemetry(parsed_data):
    score = 0
    reasons = []

    # 1. Process Check (Exact basename matching)
    for proc in parsed_data.get("processes", []):
        binary = proc.get("binary", "")
        cmd = proc.get("command", "").lower()
        basename = os.path.basename(binary).lower()
        
        # Exact match for shells
        if basename in {"sh", "bash", "dash", "zsh"}:
            score += 50
            reasons.append(f"Spawned shell: {binary}")
            
        # Flag clear exfiltration/downloaders 
        if "curl " in cmd or "wget " in cmd:
            score += 40
            reasons.append(f"Potential exfiltration command: {cmd}")

    # 2. File I/O Check
    for file_path in parsed_data.get("files_written", []):
        if file_path.startswith("/tmp/") or file_path.startswith("/etc/") or file_path.startswith("/root/"):
            score += 30
            reasons.append(f"Suspicious file write: {file_path}")

    # 3. Network Check (Known Limitation: Needs Domain Allowlist)
    for conn in parsed_data.get("network_connections", []):
        ip = conn.get("destination_ip")
        # TODO: Implement Phase 4 Category-Based Domain Allowlist (e.g., huggingface.co IPs)
        # Currently flagging all external IPs equally as a baseline constraint.
        if ip not in ["127.0.0.1", "0.0.0.0"]:
            # Any external connection is an immediate high-confidence
            # compromise indicator; it must not be diluted by other scoring.
            score = 100
            reasons.append(f"External network connection: {ip}:{conn.get('port')}")

    score = min(score, 100)
    verdict = "MALICIOUS" if score >= 60 else "BENIGN"

    return {
        "verdict": verdict,
        "risk_score": score,
        "flags": reasons
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <parsed_telemetry.json>")
        sys.exit(1)
        
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
        
    result = analyze_telemetry(data)
    print(json.dumps(result, indent=2))
