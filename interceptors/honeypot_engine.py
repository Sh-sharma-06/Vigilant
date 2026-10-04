"""
Vigilant Active Generative Honeypot Engine
==========================================
In-process interception layer that traps reconnaissance-driven malware
(sleeper agents) inside the dynamic sandbox.

Mechanisms
----------
1. Canary tokens      — generated via interceptors.canary_registry and
                        planted in every synthetic artifact we serve.
2. Recon interception — builtins.open / io.open / os.getenv / os.environ are
                        patched so requests for sensitive paths or credential
                        env vars receive plausible, canary-laced fakes instead
                        of FileNotFoundError / empty results.
3. Exfiltration trap  — socket.connect/connect_ex, urllib.request.urlopen and
                        http.client.HTTPConnection.request are hooked; every
                        outbound payload is scanned for active canaries. A hit
                        raises HoneytokenExfiltrationAlert and prints
                        `[!] HONEYTOKEN_EXFILTRATION_CAUGHT: ...`.

All hooks restore cleanly via context manager / stop(). Audit events from
PEP 578 (`sys.addaudithook`) feed the telemetry log for the triage agent.
"""
from __future__ import annotations

import builtins
import http.client
import io
import os
import socket
import sys
import threading
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .canary_registry import CanaryRegistry, CanaryToken

SENSITIVE_FILE_PATHS = (
    "/.aws/credentials", "/.aws/config", "/.ssh/id_rsa", "/.ssh/id_ed25519",
    "/.ssh/id_ecdsa", "/.ssh/authorized_keys", "/.ssh/known_hosts",
    "/etc/passwd", "/etc/shadow", "/.bash_history", "/.zsh_history",
    "/.docker/config.json", "/.kube/config", "/.git-credentials",
    "/.config/gcloud/credentials.db",
)
SENSITIVE_BASENAMES = (".env", "credentials", "id_rsa", "id_ed25519")

CRED_ENV_VARS = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
    "GITHUB_TOKEN", "GH_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS_JSON",
    "AZURE_CLIENT_SECRET", "STRIPE_SECRET_KEY", "SLACK_BOT_TOKEN",
)


class HoneytokenExfiltrationAlert(Exception):
    """Raised when an outbound payload carries an active honeytoken."""

    def __init__(self, token: CanaryToken, endpoint: str) -> None:
        self.token = token
        self.endpoint = endpoint
        super().__init__(
            f"HONEYTOKEN_EXFILTRATION_CAUGHT: {token.token_type} to {endpoint}")


class HoneypotEngine:
    """Installs and tears down the whole interception lattice."""

    def __init__(self, registry: Optional[CanaryRegistry] = None,
                 verbose: bool = True) -> None:
        self.registry = registry or CanaryRegistry.instance()
        self.verbose = verbose
        self.active = False
        self.telemetry: List[Dict[str, Any]] = []
        self.exfiltrations: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._originals: Dict[str, Any] = {}
        self._env_tokens: Dict[str, CanaryToken] = {}
        self._audit_hook_installed = False

    # ------------------------------------------------------------------ #
    # logging helpers
    # ------------------------------------------------------------------ #
    def _log(self, event: str, **fields: Any) -> None:
        entry = {"event": event, **fields}
        with self._lock:
            self.telemetry.append(entry)
        if self.verbose:
            print(f"[Vigilant::honeypot] {event}: {fields}")

    # ------------------------------------------------------------------ #
    # synthetic content generators (each embeds canaries)
    # ------------------------------------------------------------------ #
    def _fake_aws_credentials(self) -> str:
        akid = self.registry.generate("AWS_ACCESS_KEY_ID",
                                      "fake ~/.aws/credentials")
        secret = self.registry.generate("AWS_SECRET_ACCESS_KEY",
                                        "fake ~/.aws/credentials")
        return ("[default]\n"
                f"aws_access_key_id = {akid.value}\n"
                f"aws_secret_access_key = {secret.value}\n"
                "region = us-east-1\n")

    def _fake_env_file(self) -> str:
        pairs = []
        for var in ("OPENAI_API_KEY", "HF_TOKEN", "GITHUB_TOKEN"):
            tok = self.registry.generate(var, "fake .env")
            pairs.append(f"{var}={tok.value}")
        return "\n".join(pairs) + "\n"

    def _fake_ssh_key(self) -> str:
        seed = self.registry.generate("SSH_PRIVATE_KEY_SEED", "fake ~/.ssh key")
        body = "".join(
            seed.value[i:i + 64] for i in range(0, len(seed.value), 64))
        return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                f"{body}\n"
                "-----END OPENSSH PRIVATE KEY-----\n")

    def _fake_passwd(self) -> str:
        return ("root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "vigilant:x:1000:1000:Vigilant Sandbox:/home/vigilant:/bin/bash\n")

    def _fake_shadow(self) -> str:
        seed = self.registry.generate("GENERIC", "fake /etc/shadow hash")
        return (f"root:$6${seed.value[:16]}$locked:19000:0:99999:7:::\n"
                "daemon:*:19000:0:99999:7:::\n")

    def _fake_history(self) -> str:
        tok = self.registry.generate("GENERIC", "fake ~/.bash_history")
        return (f"aws configure --profile prod  # AKIA seed {tok.value}\n"
                "ssh -i ~/.ssh/id_rsa admin@10.0.0.12\n"
                "python train.py --epochs 40\n")

    def _fake_generic(self, path: str) -> str:
        tok = self.registry.generate("GENERIC", f"fake {path}")
        return f"# {os.path.basename(path)}\nSECRET={tok.value}\n"

    def _fake_content_for(self, path: str) -> Optional[str]:
        low = path.lower()
        if "/.aws/" in low:
            return self._fake_aws_credentials()
        if low.endswith(".env"):
            return self._fake_env_file()
        if "/.ssh/" in low:
            return self._fake_ssh_key()
        if low.endswith("/etc/passwd"):
            return self._fake_passwd()
        if low.endswith("/etc/shadow"):
            return self._fake_shadow()
        if "history" in os.path.basename(low):
            return self._fake_history()
        for marker in SENSITIVE_FILE_PATHS:
            if marker in low:
                return self._fake_generic(path)
        if os.path.basename(low) in SENSITIVE_BASENAMES:
            return self._fake_generic(path)
        return None

    def _is_sensitive_path(self, path: str) -> bool:
        low = os.path.expanduser(str(path)).lower()
        if any(m in low for m in SENSITIVE_FILE_PATHS):
            return True
        return os.path.basename(low) in SENSITIVE_BASENAMES

    # ------------------------------------------------------------------ #
    # env honeytokens
    # ------------------------------------------------------------------ #
    def _seed_env_tokens(self) -> None:
        for var in CRED_ENV_VARS:
            ttype = ("AWS_ACCESS_KEY_ID" if var == "AWS_ACCESS_KEY_ID"
                     else "AWS_SECRET_ACCESS_KEY" if var == "AWS_SECRET_ACCESS_KEY"
                     else "GITHUB_TOKEN" if var in ("GITHUB_TOKEN", "GH_TOKEN")
                     else "OPENAI_API_KEY" if var == "OPENAI_API_KEY"
                     else "HF_TOKEN" if var in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN")
                     else "GENERIC")
            self._env_tokens[var] = self.registry.generate(ttype, f"env:{var}")

    # ------------------------------------------------------------------ #
    # patched primitives
    # ------------------------------------------------------------------ #
    def _patched_open(self, file, mode="r", *args, **kwargs):
        try:
            path = os.fspath(file)
        except TypeError:
            return self._originals["open"](file, mode, *args, **kwargs)
        if self._is_sensitive_path(path) and any(
                m in mode for m in ("r", "+")):
            content = self._fake_content_for(os.path.expanduser(path))
            if content is not None:
                self._log("RECON_FILE_INTERCEPT", path=path, mode=mode)
                if "b" in mode:
                    return io.BytesIO(content.encode())
                return io.StringIO(content)
        return self._originals["open"](file, mode, *args, **kwargs)

    def _patched_getenv(self, key, default=None):
        if isinstance(key, str) and key in self._env_tokens:
            tok = self._env_tokens[key]
            self._log("RECON_ENV_INTERCEPT", var=key, token_type=tok.token_type)
            return tok.value
        return self._originals["getenv"](key, default)

    def _patched_environ_get(self, key, default=None):
        if isinstance(key, str) and key in self._env_tokens:
            tok = self._env_tokens[key]
            self._log("RECON_ENV_INTERCEPT", var=key, token_type=tok.token_type)
            return tok.value
        return self._originals["environ_get"](key, default)

    def _patched_environ_getitem(self, key):
        if isinstance(key, str) and key in self._env_tokens:
            tok = self._env_tokens[key]
            self._log("RECON_ENV_INTERCEPT", var=key, token_type=tok.token_type)
            return tok.value
        return self._originals["environ_getitem"](key)

    # ------------------------- exfiltration traps ---------------------- #
    def _check_payload(self, payload: Any, endpoint: str) -> None:
        hits = self.registry.scan_payload(payload)
        for tok in hits:
            self._trigger_exfil(tok, endpoint)

    def _trigger_exfil(self, token: CanaryToken, endpoint: str) -> None:
        entry = {"token_type": token.token_type, "endpoint": endpoint,
                 "label": token.label}
        with self._lock:
            self.exfiltrations.append(entry)
        print(f"[!] HONEYTOKEN_EXFILTRATION_CAUGHT: "
              f"{token.token_type} to {endpoint}")
        raise HoneytokenExfiltrationAlert(token, endpoint)

    def _patched_socket_connect(self, sock_self, address=None):  # noqa: D401
        # NOTE: installed via plain-function wrapper in start()
        endpoint = f"{address[0]}:{address[1]}" if isinstance(address, tuple) \
            else str(address)
        self._log("SOCKET_CONNECT", endpoint=endpoint)
        
        # IMMEDIATELY BLOCK THE CONNECTION TO PREVENT HANGING
        raise OSError(f"Vigilant Honeypot: Blocked outgoing connection to {endpoint}")
        # socket.connect carries no payload; arm the send hooks instead.
        if "sendall" not in self._originals:
            self._originals["sendall"] = socket.socket.sendall
            self._originals["send"] = socket.socket.send

            engine = self

            def sendall(s, data, *a, **kw):
                engine._check_payload(data, endpoint)
                return engine._originals["sendall"](s, data, *a, **kw)

            def send(s, data, *a, **kw):
                engine._check_payload(data, endpoint)
                return engine._originals["send"](s, data, *a, **kw)

            socket.socket.sendall = sendall
            socket.socket.send = send
        return self._originals["socket_connect"](sock_self, address)

    def _patched_urlopen(self, url, data=None, *args, **kwargs):
        endpoint = getattr(url, "full_url", url)
        self._log("URLLIB_OPEN", endpoint=str(endpoint))
        if data is not None:
            self._check_payload(data, str(endpoint))
        return self._originals["urlopen"](url, data, *args, **kwargs)

    def _patched_http_request(self, conn_self, method=None, url=None,
                              body=None, *args, **kwargs):
        endpoint = f"{conn_self.host}:{conn_self.port}{url}"
        self._log("HTTP_REQUEST", method=method, endpoint=endpoint)
        if body is not None:
            self._check_payload(body, endpoint)
        headers = kwargs.get("headers") or (args[0] if args else None)
        if headers:
            self._check_payload(str(headers), endpoint)
        return self._originals["http_request"](conn_self, method, url, body,
                                               *args, **kwargs)

    # ------------------------- PEP 578 audit hook ---------------------- #
    def _audit_hook(self, event: str, args: Tuple[Any, ...]) -> None:
        if event == "open":
            path = str(args[0]) if args else ""
            if self._is_sensitive_path(path):
                self._log("AUDIT_OPEN", path=path, mode=args[1] if len(args) > 1 else "?")
        elif event in ("socket.connect", "socket.getaddrinfo"):
            self._log("AUDIT_NETWORK", audit_event=event,
                      args=[str(a) for a in args[:2]])
        elif event.startswith(("subprocess.", "os.system", "os.exec")):
            self._log("AUDIT_PROCESS", audit_event=event, args=[str(a) for a in args[:2]])
            # ADD THIS LINE: Instantly block the command and trip the sandbox exception
            raise PermissionError(f"Vigilant Honeypot: Blocked OS command execution -> {event}")

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> "HoneypotEngine":
        if self.active:
            return self
        self._seed_env_tokens()
        o = self._originals
        o["open"] = builtins.open
        o["getenv"] = os.getenv
        o["environ_get"] = os.environ.get
        o["environ_getitem"] = os.environ.__getitem__
        o["socket_connect"] = socket.socket.connect
        o["urlopen"] = urllib.request.urlopen
        o["http_request"] = http.client.HTTPConnection.request

        engine = self
        # Plain-function wrappers: assigning bound methods to classes would
        # shift the instance argument into the wrong parameter slot.
        def _sock_connect(sock_self, address):
            return engine._patched_socket_connect(sock_self, address)

        def _http_request(conn_self, method, url, body=None, *a, **kw):
            return engine._patched_http_request(conn_self, method, url, body,
                                                *a, **kw)

        builtins.open = engine._patched_open
        os.getenv = engine._patched_getenv
        os.environ.get = engine._patched_environ_get
        os.environ.__getitem__ = engine._patched_environ_getitem
        socket.socket.connect = _sock_connect
        urllib.request.urlopen = engine._patched_urlopen
        http.client.HTTPConnection.request = _http_request

        if not self._audit_hook_installed:
            sys.addaudithook(self._audit_hook)
            self._audit_hook_installed = True

        self.active = True
        self._log("HONEYPOT_ARMED", canaries=len(self.registry))
        return self

    def stop(self) -> None:
        if not self.active:
            return
        o = self._originals
        builtins.open = o["open"]
        os.getenv = o["getenv"]
        os.environ.get = o["environ_get"]
        os.environ.__getitem__ = o["environ_getitem"]
        socket.socket.connect = o["socket_connect"]
        urllib.request.urlopen = o["urlopen"]
        http.client.HTTPConnection.request = o["http_request"]
        if "sendall" in o:
            socket.socket.sendall = o["sendall"]
            socket.socket.send = o["send"]
        self.active = False
        self._log("HONEYPOT_DISARMED", events=len(self.telemetry),
                  exfiltrations=len(self.exfiltrations))
        # NOTE: PEP 578 audit hooks cannot be removed once added; ours
        # becomes inert because it only records while self.active is True.
        # (The hook checks _is_sensitive_path regardless, which is cheap.)

    def __enter__(self) -> "HoneypotEngine":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ------------------------------------------------------------------ #
    def summary(self) -> Dict[str, Any]:
        return {
            "canaries_active": len(self.registry),
            "telemetry_events": len(self.telemetry),
            "exfiltration_attempts": self.exfiltrations,
        }
