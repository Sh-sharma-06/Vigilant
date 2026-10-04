import sys
import os
import json
import urllib.request

def call_gemma(prompt):
    """Communicates with Ollama and FORCES strict JSON output."""
    url = "http://localhost:11434/api/generate"
    data = json.dumps({
        "model": "gemma:2b",
        "prompt": prompt,
        "stream": False,
        "format": "json"  # <--- THIS IS THE MAGIC BULLET
    }).encode('utf-8')
    
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result.get('response', '').strip()
    except Exception as e:
        return f'{{"error": "Failed to call Gemma API: {str(e)}"}}'

def analyze_telemetry(model_name, terminal_output, strace_log_path):
    strace_data = "NO STRACE LOG"
    if os.path.exists(strace_log_path):
        with open(strace_log_path, 'r') as f:
            strace_data = "".join(f.readlines()[-300:])
        os.remove(strace_log_path)

    term_lower = terminal_output.lower()
    strace_lower = strace_data.lower()

    # Removed "invalid load key" so corrupted HF models pass safely
    suspicious_keywords = [
        "pwned", "traceback", "exception", "error", "drwxrwxrwx", "cat:",
        "httpsconnection", "socket", "operation not permitted", 
        "pip is being invoked", "stack_global","critical_hook_triggered"
    ]
    
    is_suspicious = any(word in term_lower for word in suspicious_keywords) or ("socket" in strace_lower or "execve" in strace_lower)
    
    # Fast-Path for clean models
    if not is_suspicious:
        return json.dumps({
            "model_name": model_name,
            "verdict": "BENIGN",
            "confidence": "HIGH",
            "summary": "Model loaded successfully without triggering any anomalous behavior.",
            "technical_details": "No unauthorized system calls or suspicious terminal outputs were detected by the sandbox."
        }, indent=2)

    # Deep Triage for suspicious models
    prompt = f"""You are 'Vigilant', an expert AI cybersecurity analyst. 
Analyze this model ({model_name}) detonated in a sandbox.

RULES:
- "MockClass", "invalid load key", or standard dependency errors are BENIGN (these are just corrupted files or safe mocks).
- Execution of commands, network access (socket, HTTPSConnection), or printing "pwned" is MALICIOUS.
- If the terminal output shows "Operation not permitted" or "Traceback" alongside an exploit attempt, it is MALICIOUS.

=== TERMINAL ===
{terminal_output}

=== STRACE ===
{strace_data}

Output a JSON object with exactly these keys: "model_name", "verdict" (must be "MALICIOUS" or "BENIGN"), "confidence", "summary", "technical_details".
"""
    
    print(f"[*] Suspicious activity detected. Querying Gemma API for {model_name}...")
    response = call_gemma(prompt)
    
    # Fallback if Gemma API fails
    if "Failed to call" in response:
        return response
        
    return response

if __name__ == "__main__":
    model_name = sys.argv[1]
    terminal_file = sys.argv[2]
    strace_file = "/home/sandesh/vigilant-eval-triage/logs/strace_output.log"
    
    with open(terminal_file, 'r') as f:
        term_out = f.read()
        
    report_json = analyze_telemetry(model_name, term_out, strace_file)
    
    report_path = f"/home/sandesh/vigilant-eval-triage/logs/{model_name}_report.json"
    with open(report_path, 'w') as f:
        f.write(report_json)
        
    print(f"\n[+] Analysis Complete! ESP32 Document saved.")
    print(report_json)
