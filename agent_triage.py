#!/usr/bin/env python3
"""
Vigilant Pillar 1: Semantic Triage Agent (Local Ollama qwen2.5-coder:3b)
Analyzes NEEDS_REVIEW / MALICIOUS artifacts, disassembled bytecode, and loader scripts.
Golden Rule: Never downgrades a deterministic MALICIOUS block to clean.
"""
import json
import sys
import time
import urllib.request

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "qwen2.5-coder:3b"


def call_ollama(prompt: str, timeout: int = 25) -> str | None:
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "30m",
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 320},
    }
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip()
    except Exception:
        return None


import os

GEMINI_MODEL = "gemini-3.5-flash-lite"


def call_gemini(prompt: str) -> tuple[dict | None, str | None]:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None, None
    try:
        from google import genai
        from google.genai import types
    except Exception:
        return None, None

    try:
        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.0,
            ),
        )
        data = json.loads(resp.text or "{}")
        if isinstance(data, dict) and data.get("classification"):
            return data, f"gemini:{GEMINI_MODEL}"
    except Exception:
        return None, None
    return None, None


def triage(req: dict) -> dict:
    t0 = time.perf_counter()
    name = str(req.get("name") or "artifact.bin")
    fmt = str(req.get("format") or "UNKNOWN")
    verdict = str(req.get("verdict") or "review").lower()
    root_cause = str(req.get("rootCause") or "")
    findings = req.get("findings") or []
    snippet = str(req.get("code") or "")[:1500]

    prompt = (
        "You are Vigilant's AI Model Security Triage Agent. Analyze this ML artifact and respond ONLY in valid JSON "
        'with keys: "classification" (one of "BENIGN_MATH", "NEEDS_SANDBOX", "CONFIRMED_MALICIOUS"), '
        '"confidence" (0-100 int), "summary" (1-2 concise technical sentences), '
        '"recommended_action" (1 short imperative sentence), "auto_allowlist_candidate" (boolean).\n'
        f"Artifact: {name} ({fmt})\n"
        f"Deterministic Verdict: {verdict}\n"
        f"Root Cause: {root_cause}\n"
        f"Findings: {json.dumps(findings[:4])}\n"
        f"Code/Bytecode Snippet:\n{snippet}\n"
    )

    parsed = None
    engine = f"ollama:{MODEL}"
    if verdict in ("review", "suspicious", "unknown", "needs_sandbox", ""):
        parsed, gem_engine = call_gemini(prompt)
        if parsed and gem_engine:
            engine = gem_engine

    if not isinstance(parsed, dict):
        raw_llm = call_ollama(prompt)
        engine = f"ollama:{MODEL}"
        if raw_llm:
            try:
                parsed = json.loads(raw_llm)
            except Exception:
                parsed = None

    # Fallback if Ollama daemon is asleep or returned malformed JSON
    if not isinstance(parsed, dict):
        engine = "deterministic_triage_fallback"
        low = (root_cause + " " + snippet).lower()
        if verdict == "malicious" or any(k in low for k in ("os.system", "subprocess", "socket", "eval(", "exec(", "pyfunc")):
            parsed = {
                "classification": "CONFIRMED_MALICIOUS",
                "confidence": 96,
                "summary": f"Detected host execution or exfiltration sink in {name}. Static proof confirms hostile intent.",
                "recommended_action": "Keep hard-blocked and convert weights to .safetensors if needed.",
                "auto_allowlist_candidate": False,
            }
        elif "lambda" in low and not any(k in low for k in ("import", "open", "os.", "sys.")):
            parsed = {
                "classification": "BENIGN_MATH",
                "confidence": 84,
                "summary": f"{name} contains a Keras Lambda layer with no detected OS/network sinks.",
                "recommended_action": "Sanitize via Repair Studio or detonate in Sandbox before allowlisting.",
                "auto_allowlist_candidate": True,
            }
        else:
            parsed = {
                "classification": "NEEDS_SANDBOX",
                "confidence": 75,
                "summary": f"{name} uses an executable serialization format requiring dynamic verification.",
                "recommended_action": "Run Dynamic Sandbox detonation to verify zero canary/network activity.",
                "auto_allowlist_candidate": False,
            }

    # Monotonic Safety Guardrail: LLM can NEVER override a deterministic MALICIOUS verdict
    if verdict == "malicious":
        parsed["classification"] = "CONFIRMED_MALICIOUS"
        parsed["auto_allowlist_candidate"] = False

    return {
        "ok": True,
        "engine": engine,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        "triage": parsed,
    }


if __name__ == "__main__":
    raw = sys.stdin.read().strip()
    data = json.loads(raw) if raw else {}
    print(json.dumps(triage(data)))
