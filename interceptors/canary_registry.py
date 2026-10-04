"""
Vigilant Canary Token Registry
==============================
Dynamic generation and in-memory tracking of honeytokens used by the
Active Generative Honeypot subsystem.

Tokens are stored keyed by SHA-256 fingerprint; plaintext values are only
kept inside the process for payload scanning and are never persisted.
"""
from __future__ import annotations

import hashlib
import secrets
import string
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Union


@dataclass(frozen=True)
class CanaryToken:
    """A single tracked honeytoken."""
    token_type: str          # e.g. AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN
    value: str               # the planted secret itself
    label: str               # where it was planted (fake ~/.aws/credentials, env, ...)
    created_at: float

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()


class CanaryRegistry:
    """Process-wide singleton registry of active honeytokens."""

    _instance: Optional["CanaryRegistry"] = None
    _instance_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_hash: Dict[str, CanaryToken] = {}
        self._generators = {
            "AWS_ACCESS_KEY_ID": self._gen_aws_key_id,
            "AWS_SECRET_ACCESS_KEY": self._gen_aws_secret,
            "GITHUB_TOKEN": lambda: "ghp_canary_" + self._rand(30),
            "OPENAI_API_KEY": lambda: "sk-vigilant-" + self._rand(40),
            "HF_TOKEN": lambda: "hf_vigilant" + self._rand(28),
            "SSH_PRIVATE_KEY_SEED": lambda: "VIGILANT-SSH-" + self._rand(24),
            "GENERIC": lambda: "vigilant-honey-" + self._rand(24),
        }

    @classmethod
    def instance(cls) -> "CanaryRegistry":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset(cls) -> "CanaryRegistry":
        """Drop all tokens (used by the test harness)."""
        with cls._instance_lock:
            cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------ #
    # Token generation
    # ------------------------------------------------------------------ #
    @staticmethod
    def _rand(n: int) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(n))

    def _gen_aws_key_id(self) -> str:
        suffix = "".join(secrets.choice(string.ascii_uppercase + string.digits)
                         for _ in range(8))
        return f"AKIA_VIGILANT_HONEY_{suffix}"

    def _gen_aws_secret(self) -> str:
        alphabet = string.ascii_letters + string.digits + "/+"
        return "VgHlNt" + "".join(secrets.choice(alphabet) for _ in range(34))

    def generate(self, token_type: str, label: str = "") -> CanaryToken:
        """Generate and register a fresh honeytoken of the given type."""
        gen = self._generators.get(token_type.upper(), self._generators["GENERIC"])
        return self.register(token_type.upper(), gen(), label)

    def register(self, token_type: str, value: str, label: str = "") -> CanaryToken:
        """Register an externally-created value as a honeytoken."""
        token = CanaryToken(token_type.upper(), value, label, time.time())
        with self._lock:
            self._by_hash[token.fingerprint] = token
        return token

    # ------------------------------------------------------------------ #
    # Lookups
    # ------------------------------------------------------------------ #
    def is_canary(self, candidate: str) -> bool:
        fp = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        with self._lock:
            return fp in self._by_hash

    def scan_payload(self, payload: Union[str, bytes, bytearray, memoryview, None]
                     ) -> List[CanaryToken]:
        """Return every active honeytoken found inside *payload*."""
        if payload is None:
            return []
        if isinstance(payload, str):
            data = payload.encode("utf-8", "ignore")
        else:
            data = bytes(payload)
        with self._lock:
            tokens = list(self._by_hash.values())
        hits = []
        for tok in tokens:
            if len(tok.value) < 8:        # avoid false positives on short seeds
                continue
            if tok.value.encode("utf-8") in data:
                hits.append(tok)
        return hits

    def active_tokens(self) -> List[CanaryToken]:
        with self._lock:
            return list(self._by_hash.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_hash)
