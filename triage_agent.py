from __future__ import annotations

import json
import time
from collections import Counter
from enum import Enum
from typing import Any, Optional

import requests
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    SAFE = "safe"
    MALICIOUS = "malicious"
    UNCERTAIN = "uncertain-needs-review"


class EvidenceRef(BaseModel):
    source: str = Field(default="unknown_source")
    detail: str = Field(default="No detail provided")


class Finding(BaseModel):
    finding_type: str = Field(default="unspecified_anomaly")
    severity: Severity = Field(default=Severity.INFO)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    rationale: str = Field(default="No rationale provided by model.")


class TriageResult(BaseModel):
    verdict: Verdict
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    summary: str = Field(default="No summary provided.")


class GemmaClient:
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "gemma:2b", timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str, *, json_mode: bool = False) -> str:
        payload: dict[str, Any] = {
            "model": self.model, 
            "prompt": prompt,
            "stream": False
        }
        if json_mode:
            payload["format"] = "json"
            
        resp = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "")


REASONING_PROMPT = """You are a security triage analyst reviewing an ML model file for a code-execution backdoor.

You are given three pieces of evidence:

1. STATIC SCANNER OUTPUT:
{static_json}

2. SANDBOX TELEMETRY:
{telemetry_json}

3. BASELINE DEVIATION FLAGS:
{baseline_json}

Think step by step about what each piece of evidence does and does not support. Note any contradictions. Do not reach a verdict yet — just reason.
"""

VERDICT_PROMPT = """Based on your reasoning above, produce a final verdict as a single JSON object.
You MUST output valid JSON matching EXACTLY this schema. Do NOT omit any keys such as 'rationale' or 'summary'.

{
  "verdict": "safe" | "malicious" | "uncertain-needs-review",
  "confidence": 0.9,
  "findings": [
    {
      "finding_type": "...",
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "evidence": [{"source": "...", "detail": "..."}],
      "rationale": "..."
    }
  ],
  "summary": "..."
}
"""

class TriageAgent:
    def __init__(self, client: Optional[GemmaClient] = None):
        self.client = client or GemmaClient()

    def triage(self, static_scanner_output: dict, telemetry: dict, baseline_deviation_flags: Optional[dict] = None) -> TriageResult:
        baseline_deviation_flags = baseline_deviation_flags or {"_note": "placeholder"}
        
        reasoning_prompt = REASONING_PROMPT.format(
            static_json=json.dumps(static_scanner_output, indent=2),
            telemetry_json=json.dumps(telemetry, indent=2),
            baseline_json=json.dumps(baseline_deviation_flags, indent=2),
        )
        reasoning = self.client.generate(reasoning_prompt)
        
        verdict_prompt = reasoning_prompt + "\n\nYOUR REASONING:\n" + reasoning + "\n\n" + VERDICT_PROMPT
        raw = self.client.generate(verdict_prompt, json_mode=True)
        return self._parse_verdict(raw)

    @staticmethod
    def _parse_verdict(raw: str) -> TriageResult:
        cleaned = raw.strip().strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            return TriageResult(
                verdict=Verdict.UNCERTAIN,
                confidence=0.0,
                findings=[],
                summary=f"Agent output was not valid JSON: {e}",
            )
        return TriageResult(**data)
        
    def consistency_check(
        self,
        static_scanner_output: dict,
        telemetry: dict,
        baseline_deviation_flags: Optional[dict] = None,
        runs: int = 5,
    ) -> dict:
        verdicts = []
        for _ in range(runs):
            result = self.triage(static_scanner_output, telemetry, baseline_deviation_flags)
            verdicts.append(result.verdict.value)
            time.sleep(0.1)
 
        counts = Counter(verdicts)
        majority_verdict, majority_count = counts.most_common(1)[0]
        return {
            "runs": runs,
            "verdict_counts": dict(counts),
            "majority_verdict": majority_verdict,
            "agreement_rate": majority_count / runs,
        }

if __name__ == "__main__":
    agent = TriageAgent()
    stub_static = {"opcodes": ["GLOBAL", "REDUCE"], "flagged": True}
    stub_telemetry = {"syscalls": ["connect"], "network_connections": [{"dst": "10.0.0.5", "port": 4444}]}
    
    print("[*] Running consistency check (5 runs). This will take a moment...")
    results = agent.consistency_check(stub_static, stub_telemetry, runs=5)
    print("\n[+] Consistency Check Complete:\n")
    print(json.dumps(results, indent=2))
