from __future__ import annotations

import hashlib
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

    def generate(self, prompt: str, *, json_mode: bool = False, temperature: float = 0.1) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 320,
                "temperature": temperature,
                "num_ctx": 2048,
            },
        }
        if json_mode:
            payload["format"] = "json"

        resp = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "")


TRIAGE_SINGLE_PASS_PROMPT = """You are an elite ML SecOps triage analyst inspecting an AI model file for deserialization backdoors, C2 network callbacks, and sandbox evasion.

Analyze the following three evidence sources:
1. STATIC SCANNER OUTPUT:
{static_json}

2. SANDBOX TELEMETRY (Syscalls, FakeNet C2 traffic, Canary files):
{telemetry_json}

3. BASELINE DEVIATION FLAGS:
{baseline_json}

Decision Rules:
- If SANDBOX TELEMETRY shows outbound DNS/HTTP requests, Canary access, or blocked capabilities (os.system, subprocess, exec, eval), verdict MUST be "malicious" with severity "critical".
- If STATIC SCANNER OUTPUT shows hostile imports, stack globals, or archive bit-flipping, verdict MUST be "malicious" with severity "high" or "critical".
- If static findings are benign ML metadata (e.g. tensor names like eval_accuracy) AND sandbox telemetry is completely empty/clean, verdict is "safe".

Output a single valid JSON object with these exact keys:
{{
  "verdict": "malicious",
  "confidence": 0.95,
  "findings": [
    {{
      "finding_type": "Malicious Deserialization or C2 Anomaly",
      "severity": "critical",
      "evidence": [
        {{
          "source": "static_scanner or sandbox_telemetry",
          "detail": "Exact opcode, syscall, or domain observed"
        }}
      ],
      "rationale": "Clear technical explanation of why this evidence indicates malicious or benign behavior."
    }}
  ],
  "summary": "One-sentence executive summary of the final security verdict."
}}
Allowed values for "verdict": "safe", "malicious", "uncertain-needs-review".
Allowed values for "severity": "info", "low", "medium", "high", "critical".
"""


class TriageAgent:
    _cache: dict[str, TriageResult] = {}

    def __init__(self, client: Optional[GemmaClient] = None):
        self.client = client or GemmaClient()

    def triage(
        self,
        static_scanner_output: dict,
        telemetry: dict,
        baseline_deviation_flags: Optional[dict] = None,
        *,
        use_cache: bool = True,
    ) -> TriageResult:
        baseline_deviation_flags = baseline_deviation_flags or {"_note": "none"}

        cache_key = hashlib.sha256(
            json.dumps(
                {"s": static_scanner_output, "t": telemetry, "b": baseline_deviation_flags},
                sort_keys=True,
            ).encode()
        ).hexdigest()

        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        prompt = TRIAGE_SINGLE_PASS_PROMPT.format(
            static_json=json.dumps(static_scanner_output, indent=2),
            telemetry_json=json.dumps(telemetry, indent=2),
            baseline_json=json.dumps(baseline_deviation_flags, indent=2),
        )
        raw = self.client.generate(prompt, json_mode=True, temperature=0.1 if use_cache else 0.3)
        result = self._parse_verdict(raw, static_scanner_output, telemetry)

        if use_cache:
            self._cache[cache_key] = result
        return result

    @staticmethod
    def _parse_verdict(raw: str, static_out: Optional[dict] = None, telemetry: Optional[dict] = None) -> TriageResult:
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

        # Normalize verdict string
        raw_v = str(data.get("verdict", "uncertain-needs-review")).lower().strip()
        if "malicious" in raw_v or "unsafe" in raw_v:
            data["verdict"] = Verdict.MALICIOUS.value
        elif "safe" in raw_v or "benign" in raw_v:
            data["verdict"] = Verdict.SAFE.value
        else:
            data["verdict"] = Verdict.UNCERTAIN.value

        # Normalize findings list so Gemma key variations never drop the rationale or evidence
        norm_findings = []
        raw_findings = data.get("findings", [])
        if isinstance(raw_findings, dict):
            raw_findings = [raw_findings]

        for f in raw_findings if isinstance(raw_findings, list) else []:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity", "info")).lower().strip()
            if sev not in ("info", "low", "medium", "high", "critical"):
                sev = "high" if data["verdict"] == "malicious" else "info"

            rationale = (
                f.get("rationale")
                or f.get("reason")
                or f.get("explanation")
                or f.get("description")
                or data.get("summary")
                or f"Evaluated static output ({static_out}) and runtime telemetry ({telemetry})."
            )
            if rationale in ("...", "No rationale provided by model.", ""):
                rationale = f"Correlated static indicators {static_out} with sandbox telemetry {telemetry}."

            raw_ev = f.get("evidence", [])
            if isinstance(raw_ev, dict):
                raw_ev = [raw_ev]
            norm_ev = []
            for ev in raw_ev if isinstance(raw_ev, list) else []:
                if isinstance(ev, dict):
                    norm_ev.append({
                        "source": str(ev.get("source") or ev.get("type") or "scanner"),
                        "detail": str(ev.get("detail") or ev.get("description") or ev.get("value") or static_out or telemetry),
                    })
                elif isinstance(ev, str):
                    norm_ev.append({"source": "scanner", "detail": ev})

            if not norm_ev:
                norm_ev.append({
                    "source": "pipeline_telemetry",
                    "detail": json.dumps({"static": static_out, "telemetry": telemetry})[:200],
                })

            norm_findings.append({
                "finding_type": str(f.get("finding_type") or f.get("type") or "Security Telemetry Analysis"),
                "severity": sev,
                "evidence": norm_ev,
                "rationale": str(rationale),
            })

        data["findings"] = norm_findings
        if not data.get("summary") or data.get("summary") == "...":
            data["summary"] = norm_findings[0]["rationale"] if norm_findings else "Completed automated triage analysis."

        try:
            return TriageResult(**data)
        except Exception as e:
            return TriageResult(
                verdict=Verdict.UNCERTAIN,
                confidence=0.0,
                findings=[],
                summary=f"Schema validation fallback: {e}",
            )

    def consistency_check(
        self,
        static_scanner_output: dict,
        telemetry: dict,
        baseline_deviation_flags: Optional[dict] = None,
        runs: int = 5,
    ) -> dict:
        verdicts = []
        for _ in range(runs):
            result = self.triage(static_scanner_output, telemetry, baseline_deviation_flags, use_cache=False)
            verdicts.append(result.verdict.value)
            time.sleep(0.05)

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
    stub_static = {"opcodes": ["GLOBAL", "REDUCE"], "flagged": True, "reason": "Hostile GLOBAL import: os.system"}
    stub_telemetry = {"syscalls": ["connect"], "network_connections": [{"dst": "172.20.0.2", "domain": "evil-c2-server.com", "port": 80}]}

    t0 = time.time()
    single = agent.triage(stub_static, stub_telemetry)
    print(f"[+] Single Triage Result (took {time.time() - t0:.2f}s):")
    print(single.model_dump_json(indent=2))

    print("\n[*] Running consistency check (5 runs)...")
    t1 = time.time()
    results = agent.consistency_check(stub_static, stub_telemetry, runs=5)
    print(f"\n[+] Consistency Check Complete (took {time.time() - t1:.2f}s):\n")
    print(json.dumps(results, indent=2))
